ARCHS=armv7 arm64

CFLAGS+=-I.
CFLAGS+=-Wall

include config.mk
CFLAGS+=-DFSMON_VERSION=\"$(VERSION)\"
CFLAGS+=-Icommon/ -Itrace/ -Iinclude/

LDFLAGS+=-pthread

SOURCES=main.c util.c
SOURCES+=backend/*.c
SOURCES+=trace/*.c
SOURCES+=fsmon/*.c

# LINUX: GNU / ANDROID
#     __
#  -=(o '.
#     \.-.\
#     /|  \\
#     '|  ||
#      _\_):,_

FANOTIFY_CFLAGS+=-DHAVE_FANOTIFY=1
FANOTIFY_CFLAGS+=-DHAVE_SYS_FANOTIFY=1

all: X64 ARM32 ARM64

X64:
	$(CC) -o bin/fsmon_$@ -D $@ $(CFLAGS) $(FANOTIFY_CFLAGS) $(LDFLAGS) $(SOURCES)

ARM32:
	arm-linux-gnueabi-gcc -o bin/fsmon_$@ -D $@ $(CFLAGS) $(FANOTIFY_CFLAGS) $(LDFLAGS) $(SOURCES)

ARM64:
	aarch64-linux-gnu-gcc -o bin/fsmon_$@ -D $@ $(CFLAGS) $(FANOTIFY_CFLAGS) $(LDFLAGS) $(SOURCES)

DESTDIR?=
PREFIX?=/usr

clean:
	rm -f bin/*
