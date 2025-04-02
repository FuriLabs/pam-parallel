CC = gcc
CFLAGS = -fPIC
LDFLAGS = -shared -lpam -lpthread -ljansson

TARGET = pam_parallel.so
SOURCES = src/pam_parallel.c

.PHONY: all clean

all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)
