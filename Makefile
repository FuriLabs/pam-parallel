CC = gcc
CFLAGS = -fPIC
LDFLAGS = -shared -lpam -lpthread -ljansson

TARGET = pam_parallel.so
SOURCES = src/pam_parallel.c

PREFIX ?= /usr
TRIPLET ?= $(shell $(CC) -dumpmachine)

all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install:
	install -d $(DESTDIR)$(PREFIX)/lib/$(TRIPLET)/security
	install -m 0644 $(TARGET) $(DESTDIR)$(PREFIX)/lib/$(TRIPLET)/security/

.PHONY: all clean install
