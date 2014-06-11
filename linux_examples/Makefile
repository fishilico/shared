CC ?= cc

CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
CFLAGS ?= -O2 -Wall -W -Wextra -ansi \
	-Wmissing-prototypes -Wno-unused-function -Wformat=2 \
	-fstack-protector --param=ssp-buffer-size=4 -fPIE
LDFLAGS ?= -Wl,-z,relro,-z,now -fPIE -pie

BINARIES := seccomp
SDL_BINARIES := sdl_v4l_video
ALL_BINARIES := $(BINARIES) $(SDL_BINARIES)

HAVE_SDL := $(shell pkg-config --exists sdl && echo 'y' || echo 'n')
ifeq ($(HAVE_SDL), y)
	BINARIES += $(SDL_BINARIES)
$(SDL_BINARIES): LDFLAGS += $(shell pkg-config --libs sdl)
$(SDL_BINARIES).o: CFLAGS += $(shell pkg-config --cflags sdl)
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

sdl_v4l_video: sdl_v4l_video.o
seccomp: seccomp.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
