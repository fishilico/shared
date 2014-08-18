include ../Makefile-flags.linux

PKG_CONFIG ?= pkg-config

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
$(SDL_PROGRAMS:%=%.bin): LIBS += $(shell $(PKG_CONFIG) --libs sdl)
$(SDL_PROGRAMS:%=%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags sdl)
endif

HAVE_SECCOMP := $(shell echo '\#include <linux/seccomp.h>' | \
	$(CC) -E $(CPPFLAGS) - > /dev/null 2>&1 && echo 'y' || echo 'n')
ifeq ($(HAVE_SECCOMP), y)
	PROGRAMS += $(SECCOMP_PROGRAMS)
endif

# Include subdirectories
SUBMAKEFILES := $(wildcard */Makefile)
SUBDIRS := $(filter-out modules, $(SUBMAKEFILES:%/Makefile=%))
ALL_TARGETS := $(addprefix all.., $(SUBDIRS))
CLEAN_TARGETS := $(addprefix clean.., $(SUBDIRS))

ifeq ($(shell uname -s), Linux)
all: $(PROGRAMS:%=%.bin) $(SHARED_OBJECTS) $(ALL_TARGETS)
else
all:
	@echo "Skip compilation on a non-Linux system."
endif

all..%:
	$(MAKE) -C $* all

clean: $(CLEAN_TARGETS)
	rm -f *.bin *.o *.so

clean..%:
	$(MAKE) -C $* clean

message_queue.bin: LIBS += -lrt
override_uname_dl.o: CFLAGS += -fPIC -fvisibility=hidden
override_uname_dl.so: LDFLAGS += -fPIC -shared -Wl,-soname,$@
override_uname_dl.so: LIBS += -ldl

%.bin %.so: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all all..% clean clean..%
