/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 *
 * This module is inspired by https://github.com/ChocolateLoverRaj/pam-any and uses roughly the same syntax too
 * I did not have much luck with pam-any nor do i know rust, so a reimplementation looks like a better option for me
 */

#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <jansson.h>
#include <termios.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>

static int debug_mode = 0;

static pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
static int auth_success = 0;
static int auth_result = PAM_AUTH_ERR;

static pthread_t *g_threads = NULL;
static int g_thread_count = 0;
static int *g_thread_active = NULL;

#define DEBUG_LOG(format, ...) \
    do { \
        if (debug_mode) { \
            debug_log("PAM_PARALLEL: " format, ##__VA_ARGS__); \
        } \
    } while(0)

static void debug_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vsyslog(LOG_AUTH | LOG_DEBUG, format, args);
    va_end(args);
}

typedef enum {
    MODE_ONE,  /* Succeed if any module succeeds */
    MODE_ALL   /* Succeed only if all modules succeed */
} auth_mode_t;

typedef struct module_entry {
    char *service;
    char *display_name;
    struct module_entry *next;
} module_entry_t;

typedef struct {
    auth_mode_t mode;
    module_entry_t *modules;
    int module_count;
} input_config_t;

typedef struct {
    const char *service;
    const char *display_name;
    const char *username;
    const struct pam_conv *conv;
    pthread_mutex_t *conv_mutex;
    pthread_mutex_t *result_mutex;
    int *auth_success;
    int *auth_result;
    int result;
    int thread_id;
    auth_mode_t mode;
} thread_arg_t;

static void
cancel_other_threads(int current_thread_id)
{
    if (!g_threads || !g_thread_active || g_thread_count <= 0)
        return;

    DEBUG_LOG("Attempting to cancel threads (except %d)", current_thread_id);

    for (int i = 0; i < g_thread_count; i++) {
        if (i != current_thread_id && g_threads[i] != 0 && g_thread_active[i]) {
            DEBUG_LOG("Canceling thread %d", i);

            g_thread_active[i] = 0;

            pthread_cancel(g_threads[i]);
            pthread_detach(g_threads[i]);

            g_threads[i] = 0;
            DEBUG_LOG("Thread %d canceled and detached", i);
        }
    }

    DEBUG_LOG("Thread cancellation completed");
}

static void
un_hide_input(void)
{
    struct termios term;
    if (tcgetattr(STDIN_FILENO, &term) != 0) {
        DEBUG_LOG("Failed to get terminal attributes: %s", strerror(errno));
        return;
    }

    term.c_lflag |= ECHO | ICANON;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &term) != 0)
        DEBUG_LOG("Failed to set terminal attributes: %s", strerror(errno));
    else
        DEBUG_LOG("Terminal echo restored successfully");
}

static int
pam_any_conv(int num_msg, const struct pam_message **msg,
             struct pam_response **resp, void *appdata_ptr)
{
    thread_arg_t *arg = (thread_arg_t *)appdata_ptr;
    const struct pam_conv *original_conv = arg->conv;
    char *prefixed_msg = NULL;
    struct pam_message modified_msg;
    const struct pam_message *modified_msg_ptr = &modified_msg;

    if (!g_thread_active[arg->thread_id]) {
        DEBUG_LOG("Thread %d: Skipping conversation as thread is marked inactive", arg->thread_id);
        return PAM_CONV_ERR;
    }

    /* Check if authentication already succeeded */
    pthread_mutex_lock(arg->result_mutex);
    int already_succeeded = *(arg->auth_success);
    pthread_mutex_unlock(arg->result_mutex);

    if (already_succeeded) {
        DEBUG_LOG("Thread %d: Skipping conversation as authentication already succeeded", arg->thread_id);
        return PAM_CONV_ERR;
    }

    DEBUG_LOG("Thread %d: Conversation called with %d messages", arg->thread_id, num_msg);

    pthread_mutex_lock(arg->conv_mutex);

    if (num_msg != 1 || !msg || !resp) {
        DEBUG_LOG("Thread %d: Invalid conversation parameters", arg->thread_id);
        pthread_mutex_unlock(arg->conv_mutex);
        return PAM_CONV_ERR;
    }

    DEBUG_LOG("Thread %d: Message style: %d, Content: %s",
              arg->thread_id, msg[0]->msg_style,
              msg[0]->msg ? msg[0]->msg : "(null)");

    if (msg[0]->msg) {
        size_t prefix_len = strlen(arg->display_name) + 3; /* [service_name] */
        size_t msg_len = strlen(msg[0]->msg);
        prefixed_msg = malloc(prefix_len + msg_len + 1);
        if (!prefixed_msg) {
            DEBUG_LOG("Thread %d: Failed to allocate memory for prefixed message", arg->thread_id);
            pthread_mutex_unlock(arg->conv_mutex);
            return PAM_BUF_ERR;
        }

        snprintf(prefixed_msg, prefix_len + msg_len + 1, "[%s] %s",
                 arg->display_name, msg[0]->msg);

        modified_msg.msg_style = msg[0]->msg_style;
        modified_msg.msg = prefixed_msg;

        DEBUG_LOG("Thread %d: Calling original conversation with prefixed message: %s",
                  arg->thread_id, prefixed_msg);

        if (!original_conv || !original_conv->conv) {
            DEBUG_LOG("Thread %d: Original conversation function is NULL", arg->thread_id);
            free(prefixed_msg);
            pthread_mutex_unlock(arg->conv_mutex);
            return PAM_CONV_ERR;
        }

        int ret = original_conv->conv(1, &modified_msg_ptr, resp, original_conv->appdata_ptr);
        DEBUG_LOG("Thread %d: Original conversation returned: %d", arg->thread_id, ret);

        free(prefixed_msg);
        pthread_mutex_unlock(arg->conv_mutex);
        return ret;
    }

    DEBUG_LOG("Thread %d: Empty message in conversation", arg->thread_id);
    pthread_mutex_unlock(arg->conv_mutex);
    return PAM_CONV_ERR;
}

static char *
reconstruct_json(int argc, const char **argv, int start_idx)
{
    size_t total_len = 0;
    int i;

    for (i = start_idx; i < argc; i++) {
        if (argv[i])
            total_len += strlen(argv[i]) + 1; /* +1 for space */
    }

    char *json_str = (char *)malloc(total_len + 1);
    if (!json_str)
        return NULL;

    json_str[0] = '\0';
    for (i = start_idx; i < argc; i++) {
        if (argv[i]) {
            strcat(json_str, argv[i]);
            if (i < argc - 1)
                strcat(json_str, " ");
        }
    }

    return json_str;
}

static int
service_exists(const char *service)
{
    char path[256];
    int exists = 0;

    snprintf(path, sizeof(path), "/etc/pam.d/%s", service);
    exists = (access(path, F_OK) == 0);

    DEBUG_LOG("Checking for PAM service %s: %s", service, exists ? "Found" : "Not found");

    return exists;
}

static int
parse_input(const char *arg_string, input_config_t *config)
{
    DEBUG_LOG("Parsing input: %s", arg_string);

    json_error_t error;
    json_t *root = json_loads(arg_string, 0, &error);

    if (!root) {
        DEBUG_LOG("JSON parsing error: %s (line: %d, col: %d)",
                  error.text, error.line, error.column);
        return PAM_AUTH_ERR;
    }

    json_t *mode_json = json_object_get(root, "mode");
    if (!json_is_string(mode_json)) {
        DEBUG_LOG("Mode is not a string or is missing");
        json_decref(root);
        return PAM_AUTH_ERR;
    }

    const char *mode_str = json_string_value(mode_json);
    DEBUG_LOG("Mode value: %s", mode_str);

    if (strcmp(mode_str, "One") == 0) {
        config->mode = MODE_ONE;
        DEBUG_LOG("Mode set to ONE");
    } else if (strcmp(mode_str, "All") == 0) {
        config->mode = MODE_ALL;
        DEBUG_LOG("Mode set to ALL");
    } else {
        DEBUG_LOG("Invalid mode value: %s", mode_str);
        json_decref(root);
        return PAM_AUTH_ERR;
    }

    json_t *modules_json = json_object_get(root, "modules");
    if (!json_is_object(modules_json)) {
        DEBUG_LOG("Modules is not an object or is missing");
        json_decref(root);
        return PAM_AUTH_ERR;
    }

    config->module_count = 0;
    config->modules = NULL;
    module_entry_t *last = NULL;

    const char *service;
    json_t *display_name;

    DEBUG_LOG("Processing modules:");
    json_object_foreach(modules_json, service, display_name) {
        if (!json_is_string(display_name)) {
            DEBUG_LOG("Display name for service %s is not a string, skipping", service);
            continue;
        }

        if (!service_exists(service)) {
            DEBUG_LOG("ERROR: PAM service '%s' does not exist, aborting", service);

            module_entry_t *current = config->modules;
            while (current) {
                module_entry_t *next = current->next;
                free(current->service);
                free(current->display_name);
                free(current);
                current = next;
            }

            json_decref(root);
            return PAM_SERVICE_ERR;
        }

        module_entry_t *entry = malloc(sizeof(module_entry_t));
        if (!entry) {
            DEBUG_LOG("Memory allocation failed for module entry");

            module_entry_t *current = config->modules;
            while (current) {
                module_entry_t *next = current->next;
                free(current->service);
                free(current->display_name);
                free(current);
                current = next;
            }
            json_decref(root);
            return PAM_BUF_ERR;
        }

        entry->service = strdup(service);
        entry->display_name = strdup(json_string_value(display_name));
        entry->next = NULL;

        DEBUG_LOG("Added module: %s (display: %s)", entry->service, entry->display_name);

        if (last)
            last->next = entry;
        else
            config->modules = entry;

        last = entry;
        config->module_count++;
    }

    if (config->module_count == 0) {
        DEBUG_LOG("No valid modules found, aborting");
        json_decref(root);
        return PAM_SERVICE_ERR;
    }

    DEBUG_LOG("Total modules found: %d", config->module_count);

    json_decref(root);
    return PAM_SUCCESS;
}

static void
free_config(input_config_t *config)
{
    DEBUG_LOG("Freeing configuration resources");

    module_entry_t *current = config->modules;
    while (current) {
        module_entry_t *next = current->next;
        free(current->service);
        free(current->display_name);
        free(current);
        current = next;
    }

    config->modules = NULL;
}

static void *
module_auth_thread(void *arg)
{
    thread_arg_t *thread_arg = (thread_arg_t *)arg;
    pam_handle_t *pamh = NULL;
    struct pam_conv pam_conversation = {
        .conv = pam_any_conv,
        .appdata_ptr = thread_arg
    };

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    DEBUG_LOG("Thread %d: Starting authentication for service %s",
              thread_arg->thread_id, thread_arg->service);

    int ret = pam_start(thread_arg->service, thread_arg->username, &pam_conversation, &pamh);
    if (ret != PAM_SUCCESS) {
        DEBUG_LOG("Thread %d: pam_start failed with error %d: %s",
                  thread_arg->thread_id, ret, pam_strerror(pamh, ret));
        thread_arg->result = ret;
        return NULL;
    }

    DEBUG_LOG("Thread %d: pam_start successful, attempting authentication",
              thread_arg->thread_id);

    int retry_count = 0;
    int max_retries = 3;

    while (retry_count < max_retries) {
        if (!g_thread_active[thread_arg->thread_id]) {
            DEBUG_LOG("Thread %d: Terminating as thread is marked inactive", thread_arg->thread_id);
            pam_end(pamh, PAM_SUCCESS);
            return NULL;
        }

        /* Check if authentication already succeeded in another thread */
        pthread_mutex_lock(thread_arg->result_mutex);
        int already_succeeded = *(thread_arg->auth_success);
        pthread_mutex_unlock(thread_arg->result_mutex);

        if (already_succeeded) {
            DEBUG_LOG("Thread %d: Skipping authentication as it already succeeded elsewhere",
                      thread_arg->thread_id);
            pam_end(pamh, PAM_SUCCESS);
            return NULL;
        }

        ret = pam_authenticate(pamh, 0);
        DEBUG_LOG("Thread %d: pam_authenticate returned %d: %s",
                  thread_arg->thread_id, ret, pam_strerror(pamh, ret));

        if (ret == PAM_SUCCESS) {
            thread_arg->result = PAM_SUCCESS;
            un_hide_input();

            if (thread_arg->mode == MODE_ONE) {
                pthread_mutex_lock(thread_arg->result_mutex);
                *(thread_arg->auth_success) = 1;
                *(thread_arg->auth_result) = PAM_SUCCESS;
                pthread_mutex_unlock(thread_arg->result_mutex);

                DEBUG_LOG("Thread %d: Authentication successful, canceling other threads",
                          thread_arg->thread_id);
                cancel_other_threads(thread_arg->thread_id);
            }

            break;
        } else if (ret == PAM_AUTH_ERR && retry_count < max_retries - 1) {
            DEBUG_LOG("Thread %d: Authentication failed, retry %d/%d",
                      thread_arg->thread_id, retry_count + 1, max_retries);
            retry_count++;
            /* Don't return immediately, give other methods a chance too */
            usleep(100000);
            continue;
        } else {
            thread_arg->result = ret;
            break;
        }
    }

    DEBUG_LOG("Thread %d: Ending PAM session with result %d",
              thread_arg->thread_id, thread_arg->result);
    pam_end(pamh, ret);
    return NULL;
}

static int
find_json_start(int argc, const char **argv)
{
    for (int i = 0; i < argc; i++) {
        if (argv[i] && strchr(argv[i], '{') != NULL)
            return i;
    }
    return -1;
}

static int
check_debug_flag(int argc, const char **argv)
{
    for (int i = 0; i < argc; i++) {
        if (argv[i] && strcmp(argv[i], "debug") == 0)
            return 1;
    }
    return 0;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char **argv)
{
    int ret;
    const char *username = NULL;
    const struct pam_conv *conv = NULL;
    input_config_t config;
    pthread_mutex_t conv_mutex = PTHREAD_MUTEX_INITIALIZER;
    thread_arg_t *thread_args = NULL;

    auth_success = 0;
    auth_result = PAM_AUTH_ERR;

    openlog("pam_parallel", LOG_PID, LOG_AUTH);
    debug_mode = check_debug_flag(argc, argv);

    DEBUG_LOG("=== PAM Parallel module started ===");
    DEBUG_LOG("Flags: %d, Argc: %d", flags, argc);

    for (int i = 0; i < argc; i++) {
        DEBUG_LOG("Arg %d: %s", i, argv[i] ? argv[i] : "(null)");
    }

    int json_start = find_json_start(argc, argv);
    if (json_start < 0) {
        DEBUG_LOG("No JSON configuration found in arguments");
        return PAM_AUTH_ERR;
    }

    char *json_config = reconstruct_json(argc, argv, json_start);
    if (!json_config) {
        DEBUG_LOG("Failed to reconstruct JSON configuration");
        return PAM_BUF_ERR;
    }

    DEBUG_LOG("Reconstructed JSON configuration: %s", json_config);

    ret = parse_input(json_config, &config);
    free(json_config);

    if (ret != PAM_SUCCESS) {
        DEBUG_LOG("Failed to parse input configuration: %d", ret);
        return ret;
    }

    ret = pam_get_user(pamh, &username, NULL);
    if (ret != PAM_SUCCESS) {
        DEBUG_LOG("Failed to get username: %d", ret);
        free_config(&config);
        return ret;
    }

    DEBUG_LOG("Username: %s", username);

    ret = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (ret != PAM_SUCCESS || !conv) {
        DEBUG_LOG("Failed to get conversation structure: %d", ret);
        free_config(&config);
        return PAM_CONV_ERR;
    }

    DEBUG_LOG("Got conversation structure: %p, conv function: %p",
              (void*)conv, (void*)(conv ? conv->conv : NULL));

    g_threads = calloc(config.module_count, sizeof(pthread_t));
    thread_args = calloc(config.module_count, sizeof(thread_arg_t));
    g_thread_active = calloc(config.module_count, sizeof(int));

    if (!g_threads || !thread_args || !g_thread_active) {
        DEBUG_LOG("Memory allocation failed for threads");
        free_config(&config);
        free(g_threads);
        free(thread_args);
        free((void *)g_thread_active);
        g_threads = NULL;
        g_thread_active = NULL;
        return PAM_BUF_ERR;
    }

    g_thread_count = config.module_count;

    /* Initialize all threads as active */
    for (int i = 0; i < g_thread_count; i++) {
        g_thread_active[i] = 1;
    }

    int i = 0;
    module_entry_t *current = config.modules;
    while (current) {
        thread_args[i].service = current->service;
        thread_args[i].display_name = current->display_name;
        thread_args[i].username = username;
        thread_args[i].conv = conv;
        thread_args[i].conv_mutex = &conv_mutex;
        thread_args[i].result_mutex = &result_mutex;
        thread_args[i].auth_success = &auth_success;
        thread_args[i].auth_result = &auth_result;
        thread_args[i].result = PAM_AUTH_ERR;
        thread_args[i].thread_id = i;
        thread_args[i].mode = config.mode;

        DEBUG_LOG("Creating thread %d for service %s", i, current->service);

        int thread_ret = pthread_create(&g_threads[i], NULL, module_auth_thread, &thread_args[i]);
        if (thread_ret != 0)
            DEBUG_LOG("Failed to create thread %d: %s", i, strerror(thread_ret));

        current = current->next;
        i++;
    }

    int success_count = 0;
    int failure_count = 0;
    ret = PAM_AUTH_ERR;

    DEBUG_LOG("Waiting for authentication threads to complete");

    for (i = 0; i < config.module_count; i++) {
        if (g_thread_active[i] && thread_args[i].result == PAM_SUCCESS) {
            success_count++;
            DEBUG_LOG("Thread %d already succeeded, success count now: %d", i, success_count);

            if (config.mode == MODE_ONE) {
                /* In ONE mode, one success is enough */
                DEBUG_LOG("ONE mode: authentication successful via thread %d", i);
                ret = PAM_SUCCESS;
                cancel_other_threads(i);
                break;
            }
        }
    }

    if (!(config.mode == MODE_ONE && success_count > 0)) {
        for (i = 0; i < config.module_count; i++) {
            if (g_threads[i] != 0 && g_thread_active[i]) {
                int join_attempts = 0;
                int max_join_attempts = 30;
                int join_result = -1;

                while (join_attempts < max_join_attempts) {
                    join_result = pthread_join(g_threads[i], NULL);

                    if (join_result == 0) {
                        /* Thread joined successfully */
                        break;
                    } else if (join_result == EBUSY) {
                        /* Thread still running */
                        join_attempts++;
                        usleep(100000);
                        continue;
                    } else {
                        DEBUG_LOG("Thread %d join error: %s", i, strerror(join_result));
                        break;
                    }
                }

                if (join_result == 0) {
                    DEBUG_LOG("Thread %d completed with result: %d", i, thread_args[i].result);

                    if (thread_args[i].result == PAM_SUCCESS) {
                        success_count++;
                        DEBUG_LOG("Thread %d succeeded, success count now: %d", i, success_count);

                        if (config.mode == MODE_ONE) {
                            /* In ONE mode, one success is enough */
                            DEBUG_LOG("ONE mode: authentication successful via thread %d", i);
                            ret = PAM_SUCCESS;
                            cancel_other_threads(i);
                            break;
                        }
                    } else {
                        failure_count++;
                        DEBUG_LOG("Thread %d failed, failure count now: %d", i, failure_count);

                        if (config.mode == MODE_ALL) {
                            /* In ALL mode, one failure means overall failure */
                            DEBUG_LOG("ALL mode: authentication failed due to thread %d", i);
                            ret = PAM_AUTH_ERR;
                            cancel_other_threads(-1);
                            break;
                        }
                    }
                } else {
                    DEBUG_LOG("Thread %d join timed out after %d attempts, treating as failure",
                              i, max_join_attempts);
                    pthread_cancel(g_threads[i]);
                    pthread_detach(g_threads[i]);
                    g_thread_active[i] = 0;
                    failure_count++;

                    if (config.mode == MODE_ALL) {
                        DEBUG_LOG("ALL mode: authentication failed due to thread %d timeout", i);
                        ret = PAM_AUTH_ERR;
                        cancel_other_threads(-1);
                        break;
                    }
                }
            }
        }
    }

    if (config.mode == MODE_ONE && success_count == 0) {
        DEBUG_LOG("ONE mode: all modules failed, authentication failed");
        ret = PAM_AUTH_ERR;
    } else if (config.mode == MODE_ALL && failure_count == 0 && success_count == config.module_count) {
        DEBUG_LOG("ALL mode: all modules succeeded, authentication successful");
        ret = PAM_SUCCESS;
    }

    if (config.mode == MODE_ONE && success_count > 0)
        ret = PAM_SUCCESS;

    DEBUG_LOG("Final result: %d (success: %d, failure: %d)", ret, success_count, failure_count);

    free(g_threads);
    free(thread_args);
    free((void *)g_thread_active);
    g_threads = NULL;
    g_thread_active = NULL;
    g_thread_count = 0;
    free_config(&config);
    pthread_mutex_destroy(&conv_mutex);
    pthread_mutex_destroy(&result_mutex);

    DEBUG_LOG("=== PAM Parallel module finished with result %d ===", ret);
    closelog();

    return ret;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    debug_mode = check_debug_flag(argc, argv);
    DEBUG_LOG("pam_sm_setcred called with flags: %d", flags);
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    debug_mode = check_debug_flag(argc, argv);
    DEBUG_LOG("pam_sm_acct_mgmt called with flags: %d", flags);
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    debug_mode = check_debug_flag(argc, argv);
    DEBUG_LOG("pam_sm_open_session called with flags: %d", flags);
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    debug_mode = check_debug_flag(argc, argv);
    DEBUG_LOG("pam_sm_close_session called with flags: %d", flags);
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    debug_mode = check_debug_flag(argc, argv);
    DEBUG_LOG("pam_sm_chauthtok called with flags: %d", flags);
    return PAM_SUCCESS;
}
