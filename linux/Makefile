include ../linux-flags.mk

PKG_CONFIG ?= pkg-config

# Programs which need specific options
KVM_PROGRAMS := kvm_base
LIBMNL_PROGRAMS := enum_link_addrs
NETLINK_PROGRAMS := crypto_socket
PULSE_PROGRAMS := pulseaudio_echo
SDL_PROGRAMS := sdl_v4l_video
SECCOMP_PROGRAMS := seccomp
SHARED_OBJECTS := override_uname_dl.$(LIB_EXT)

# Programs not to test automatically, because they hang
NONTEST_PROGRAMS := inotify_tmp pulseaudio_echo sdl_v4l_video xterm_mouse
NONTEST_BINARIES := $(NONTEST_PROGRAMS:%=%.$(BIN_EXT)) override_uname_dl.sh

# Find other programs. Only programs in $(PROGRAMS) are built.
SOURCES := $(wildcard *.c)
ALL_PROGRAMS := $(filter-out $(SHARED_OBJECTS:%.$(LIB_EXT)=%), $(SOURCES:%.c=%))
PROGRAMS := $(filter-out \
	$(KVM_PROGRAMS) $(LIBMNL_PROGRAMS) $(NETLINK_PROGRAMS) $(PULSE_PROGRAMS) \
	$(SDL_PROGRAMS) $(SECCOMP_PROGRAMS), $(ALL_PROGRAMS))

HAVE_KVM := $(call ccpp-has-option,-include linux/kvm.h)
ifeq ($(HAVE_KVM), y)
	PROGRAMS += $(KVM_PROGRAMS)
endif

HAVE_NETLINK := $(call ccpp-has-option,-include linux/netlink.h)
HAVE_LIBMNL := $(shell $(PKG_CONFIG) --exists libmnl && echo 'y' || echo 'n')
ifeq ($(HAVE_NETLINK), y)
	PROGRAMS += $(NETLINK_PROGRAMS)
	ifeq ($(HAVE_LIBMNL), y)
		PROGRAMS += $(LIBMNL_PROGRAMS)
$(LIBMNL_PROGRAMS:%=%.$(BIN_EXT)): LIBS += $(shell $(PKG_CONFIG) --libs libmnl)
$(LIBMNL_PROGRAMS:%=.%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags libmnl)
	endif
endif

HAVE_PULSE := $(shell $(PKG_CONFIG) --exists libpulse && echo 'y' || echo 'n')
ifeq ($(HAVE_PULSE), y)
	PROGRAMS += $(PULSE_PROGRAMS)
$(PULSE_PROGRAMS:%=%.$(BIN_EXT)): LIBS += $(shell $(PKG_CONFIG) --libs libpulse)
$(PULSE_PROGRAMS:%=.%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags libpulse) --std=c99
endif

HAVE_SDL2 := $(shell $(PKG_CONFIG) --exists sdl2 && echo 'y' || echo 'n')
ifeq ($(HAVE_SDL2), y)
	PROGRAMS += $(SDL_PROGRAMS)
$(SDL_PROGRAMS:%=%.$(BIN_EXT)): LIBS += $(shell $(PKG_CONFIG) --libs sdl2)
$(SDL_PROGRAMS:%=.%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags sdl2)
endif

HAVE_SECCOMP := $(call ccpp-has-option,-include linux/seccomp.h)
ifeq ($(HAVE_SECCOMP), y)
	PROGRAMS += $(SECCOMP_PROGRAMS)
endif

TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(PROGRAMS:%=%.$(BIN_EXT)) $(wildcard *.py) $(wildcard *.sh))

all: $(PROGRAMS:%=%.$(BIN_EXT)) $(SHARED_OBJECTS)
	@:

clean:
	$(CLEAN_CMD)

list-nobuild:
	@echo $(filter-out $(PROGRAMS), $(ALL_PROGRAMS))

test: all
	@$(call run-test-progs,$(filter-out eventpoll_activetty.$(BIN_EXT), $(TEST_BINARIES))) && \
	if [ -r /sys/class/tty/tty0/active ] ; then \
		$(call run-test-progs,eventpoll_activetty.$(BIN_EXT)) < /dev/null ; \
	fi

.crypto_socket.o: CFLAGS += $(call cc-disable-warning,strict-aliasing)
message_queue.$(BIN_EXT): LIBS += -lrt
.override_uname_dl.o: CFLAGS += $(LIB_CFLAGS)
override_uname_dl.$(LIB_EXT): LIBS += -ldl

%.$(BIN_EXT): .%.o
	$(V_CCLD)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.$(LIB_EXT): .%.o
	$(V_CCLD)$(CC) $(filter-out -fPIC -fPIE -pie -shared, $(LDFLAGS)) $(LIB_LDFLAGS) -o $@ $^ $(LIBS)

.%.o: %.c
	$(V_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean list-nobuild test
.PRECIOUS: .%.o

-include .*.d
