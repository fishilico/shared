CC ?= cc
PKG_CONFIG ?= pkg-config

include ../Makefile-flags.linux

# Programs which need specific options
SDL_PROGRAMS := sdl_v4l_video
SECCOMP_PROGRAMS := seccomp
SHARED_OBJECTS := override_uname_dl.so

# Find other programs. Only programs in $(PROGRAMS) are built.
SOURCES := $(wildcard *.c)
ALL_PROGRAMS := $(filter-out $(SHARED_OBJECTS:%.so=%), $(SOURCES:%.c=%))
PROGRAMS := $(filter-out $(SDL_PROGRAMS) $(SECCOMP_PROGRAMS), $(ALL_PROGRAMS))

HAVE_SDL := $(shell $(PKG_CONFIG) --exists sdl && echo 'y' || echo 'n')
ifeq ($(HAVE_SDL), y)
	PROGRAMS += $(SDL_PROGRAMS)
$(SDL_PROGRAMS:%=%.bin): LDFLAGS += $(shell $(PKG_CONFIG) --libs sdl)
$(SDL_PROGRAMS:%=%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags sdl)
endif

HAVE_SECCOMP := $(shell echo '\#include <linux/seccomp.h>' | \
	$(CC) -E $(CPPFLAGS) - > /dev/null 2>&1 && echo 'y' || echo 'n')
ifeq ($(HAVE_SECCOMP), y)
	PROGRAMS += $(SECCOMP_PROGRAMS)
endif

ifeq ($(shell uname -s), Linux)
all: $(PROGRAMS:%=%.bin) $(SHARED_OBJECTS)
else
all:
	@echo "Skip compilation on a non-Linux system."
endif

clean:
	rm -f *.bin *.o *.so

message_queue.bin: LDFLAGS += -lrt
override_uname_dl.o: CFLAGS += -fPIC -shared -fvisibility=hidden
override_uname_dl.so: LDFLAGS += -fPIC -shared -Wl,-soname,$@ -ldl

%.bin %.so: %.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
