include ../linux-flags.mk

PKG_CONFIG ?= pkg-config

# Programs which need specific options
NETLINK_PROGRAMS := enum_link_addrs
SDL_PROGRAMS := sdl_v4l_video
SECCOMP_PROGRAMS := seccomp
SHARED_OBJECTS := override_uname_dl.$(LIB_EXT)

# Programs not to test automatically, because they hang
NONTEST_PROGRAMS := inotify_tmp sdl_v4l_video xterm_mouse
NONTEST_BINARIES := $(NONTEST_PROGRAMS:%=%.$(BIN_EXT)) override_uname_dl.sh

# Find other programs. Only programs in $(PROGRAMS) are built.
SOURCES := $(wildcard *.c)
ALL_PROGRAMS := $(filter-out $(SHARED_OBJECTS:%.$(LIB_EXT)=%), $(SOURCES:%.c=%))
PROGRAMS := $(filter-out $(NETLINK_PROGRAMS) $(SDL_PROGRAMS) $(SECCOMP_PROGRAMS), $(ALL_PROGRAMS))

# libnetlink is provided by iproute2 project
HAVE_NETLINK := $(shell echo '\#include <libnetlink.h>' | \
	$(CC) -E $(CPPFLAGS) - > /dev/null 2>&1 && echo 'y' || echo 'n')
ifeq ($(HAVE_NETLINK), y)
	PROGRAMS += $(NETLINK_PROGRAMS)
endif

HAVE_SDL := $(shell $(PKG_CONFIG) --exists sdl && echo 'y' || echo 'n')
ifeq ($(HAVE_SDL), y)
	PROGRAMS += $(SDL_PROGRAMS)
$(SDL_PROGRAMS:%=%.$(BIN_EXT)): LIBS += $(shell $(PKG_CONFIG) --libs sdl)
$(SDL_PROGRAMS:%=%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags sdl)
endif

HAVE_SECCOMP := $(shell echo '\#include <linux/seccomp.h>' | \
	$(CC) -E $(CPPFLAGS) - > /dev/null 2>&1 && echo 'y' || echo 'n')
ifeq ($(HAVE_SECCOMP), y)
	PROGRAMS += $(SECCOMP_PROGRAMS)
endif

TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(PROGRAMS:%=%.$(BIN_EXT)) $(wildcard *.py) $(wildcard *.sh))

all: $(PROGRAMS:%=%.$(BIN_EXT)) $(SHARED_OBJECTS)

clean:
	rm -f *.bin *.o *.so

test: all
	@for P in $(sort $(filter-out eventpoll_activetty.$(BIN_EXT), $(TEST_BINARIES))); do \
		echo ./$$P && ./$$P || exit $$? ; \
	done && \
	if [ -r /sys/class/tty/tty0/active ] ; then \
		echo ./eventpoll_activetty.$(BIN_EXT) && \
		./eventpoll_activetty.$(BIN_EXT) < /dev/null || exit $$? ; \
	fi

enum_link_addrs.$(BIN_EXT): LIBS += -lnetlink
message_queue.$(BIN_EXT): LIBS += -lrt
override_uname_dl.o: CFLAGS += $(LIB_CFLAGS)
override_uname_dl.$(LIB_EXT): LIBS += -ldl

%.$(BIN_EXT): %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.$(LIB_EXT): %.o
	$(CC) $(filter-out -fPIC -fPIE -pie -shared, $(LDFLAGS)) $(LIB_LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean test
