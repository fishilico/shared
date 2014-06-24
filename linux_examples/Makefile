CC ?= cc

CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
CFLAGS ?= -O2 -Wall -W -Wextra -ansi \
	-Wmissing-prototypes -Wno-unused-function -Wformat=2 \
	-fstack-protector --param=ssp-buffer-size=4 -fPIE
LDFLAGS ?= -Wl,-z,relro,-z,now,--no-undefined -fPIE -pie

BINARIES := override_uname_dl.so read_vdso
SDL_BINARIES := sdl_v4l_video
SECCOMP_BINARIES := seccomp
ALL_BINARIES := $(BINARIES) $(SDL_BINARIES) $(SECCOMP_BINARIES)

HAVE_SDL := $(shell pkg-config --exists sdl && echo 'y' || echo 'n')
ifeq ($(HAVE_SDL), y)
	BINARIES += $(SDL_BINARIES)
$(SDL_BINARIES): LDFLAGS += $(shell pkg-config --libs sdl)
$(SDL_BINARIES).o: CFLAGS += $(shell pkg-config --cflags sdl)
endif

HAVE_SECCOMP := $(shell echo '\#include <linux/seccomp.h>' | \
	$(CC) -E $(CPPFLAGS) - > /dev/null 2>&1 && echo 'y' || echo 'n')
ifeq ($(HAVE_SECCOMP), y)
	BINARIES += $(SECCOMP_BINARIES)
endif

ifeq ($(shell uname -s), Linux)
all: $(BINARIES)
else
all:
	@echo "Skip compilation on a non-Linux system."
endif

clean:
	rm -f *.o
	rm -f $(ALL_BINARIES)

override_uname_dl.o: CFLAGS += -fPIC -shared -fvisibility=hidden
override_uname_dl.so: LDFLAGS += -fPIC -shared -Wl,-soname,$@ -ldl

read_vdso: read_vdso.o
	$(CC) -o $@ $^ $(LDFLAGS)

sdl_v4l_video: sdl_v4l_video.o
	$(CC) -o $@ $^ $(LDFLAGS)

seccomp: seccomp.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.so: %.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
