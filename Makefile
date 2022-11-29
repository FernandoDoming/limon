include config.mk
TRACYDIR=libtracy/

CFLAGS+=-I.
CFLAGS+=-Wall

CFLAGS+=-DLIMON_VERSION=\"$(VERSION)\"
CFLAGS+=-Icommon/ -Itrace/ -Idump/ -I$(TRACYDIR) -g

LDFLAGS+=-pthread

SOURCES=main.c util.c
SOURCES+=backend/*.c
SOURCES+=trace/*.c
SOURCES+=dump/*.c
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

all: tracy limon

limon: $(SOURCES)
	mkdir -p bin
	$(CC) -o bin/limon $(CFLAGS) $(FANOTIFY_CFLAGS) $(LDFLAGS) $(SOURCES)

tracy:
	cd $(TRACYDIR) && $(MAKE) && $(MAKE) clean

DESTDIR?=
PREFIX?=/usr

clean:
	rm -f bin/* lib/*
