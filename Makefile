include config.mk
TRACYDIR=libtracy/

CFLAGS+=-I.
CFLAGS+=-Wall

CFLAGS+=-DLIMON_VERSION=\"$(VERSION)\"
CFLAGS+=-Icommon/ -Itrace/ -I$(TRACYDIR)

LDFLAGS+=-pthread

SOURCES=main.c util.c
SOURCES+=backend/*.c
SOURCES+=trace/*.c
SOURCES+=lib/libtracy.a

# LINUX
#     __
#  -=(o '.
#     \.-.\
#     /|  \\
#     '|  ||
#      _\_):,_

FANOTIFY_CFLAGS+=-DHAVE_FANOTIFY=1
FANOTIFY_CFLAGS+=-DHAVE_SYS_FANOTIFY=1

all: tracy X64

X64: $(SOURCES)
	$(CC) -o bin/limon_$@ -D $@ $(CFLAGS) $(FANOTIFY_CFLAGS) $(LDFLAGS) $(SOURCES)

ARM32: $(SOURCES)
	arm-linux-gnueabi-gcc -o bin/limon_$@ -D $@ $(CFLAGS) $(FANOTIFY_CFLAGS) $(LDFLAGS) $(SOURCES)

ARM64: $(SOURCES)
	aarch64-linux-gnu-gcc -o bin/limon_$@ -D $@ $(CFLAGS) $(FANOTIFY_CFLAGS) $(LDFLAGS) $(SOURCES)

tracy:
	cd $(TRACYDIR) && $(MAKE) && $(MAKE) clean

DESTDIR?=
PREFIX?=/usr

clean:
	rm -f bin/* lib/*
