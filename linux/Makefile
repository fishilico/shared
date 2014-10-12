include ../linux-flags.mk

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

all: $(PROGRAMS:%=%.bin) $(SHARED_OBJECTS)

clean:
	rm -f *.bin *.o *.so

enum_link_addrs.bin: LIBS += -lnetlink
message_queue.bin: LIBS += -lrt
override_uname_dl.o: CFLAGS += -fPIC -fvisibility=hidden
override_uname_dl.so: LDFLAGS += -fPIC -shared -Wl,-soname,$@
override_uname_dl.so: LIBS += -ldl

%.bin %.so: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
