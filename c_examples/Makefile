CC ?= cc
# C preprocessor flags
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
# C compiler flags
CFLAGS ?= -O2 -Wall -W -Wextra -ansi -pedantic \
	-Wmissing-prototypes -Wno-unused-function -Wformat=2 \
	-fstack-protector --param=ssp-buffer-size=4 -fPIE
# Linker flags
LDFLAGS ?= -Wl,-z,relro,-z,now -fPIE -pie

BINARIES := cpuid view_sizes
OPENMP_BINARIES := openmp_matrix
GTK_BINARIES := gtk_alpha_window
SDL_BINARIES := sdl_v4l_video
ALL_BINARIES := $(BINARIES) $(OPENMP_BINARIES) $(GTK_BINARIES) $(SDL_BINARIES)

# view_sizes.c uses "long long" type, so disable the related warning
view_sizes.o: CFLAGS += -Wno-long-long

# clang doesn't support OPENMP yet
ifneq ($(CC), clang)
# when gcc is not compiled with pthread, -fopenmp makes the preprocessor fails
ifeq ($(shell $(CC) -fopenmp -E - < /dev/null > /dev/null 2>&1 && echo y), y)
BINARIES += $(OPENMP_BINARIES)
$(OPENMP_BINARIES): LDFLAGS += -fopenmp
$(OPENMP_BINARIES).o: CFLAGS += -fopenmp
endif
endif

HAVE_GTK3 := $(shell pkg-config --exists gtk+-3.0 && echo 'y' || echo 'n')
ifeq ($(HAVE_GTK3), y)
	BINARIES += $(GTK_BINARIES)
$(GTK_BINARIES): LDFLAGS += $(shell pkg-config --libs gtk+-3.0)
$(GTK_BINARIES).o: CFLAGS += $(shell pkg-config --cflags gtk+-3.0)
else
	HAVE_GTK2 := $(shell pkg-config --exists gtk+-2.0 && echo 'y' || echo 'n')
	ifeq ($(HAVE_GTK2), y)
		BINARIES += $(GTK_BINARIES)
$(GTK_BINARIES): LDFLAGS += $(shell pkg-config --libs gtk+-2.0)
$(GTK_BINARIES).o: CFLAGS += $(shell pkg-config --cflags gtk+-2.0)
	endif
endif

HAVE_SDL := $(shell pkg-config --exists sdl && echo 'y' || echo 'n')
ifeq ($(HAVE_SDL), y)
	BINARIES += $(SDL_BINARIES)
$(SDL_BINARIES): LDFLAGS += $(shell pkg-config --libs sdl)
$(SDL_BINARIES).o: CFLAGS += $(shell pkg-config --cflags sdl)
endif

all: $(BINARIES)

clean:
	rm -f *.o
	rm -f $(ALL_BINARIES)

cpuid: cpuid.o
gtk_alpha_window: gtk_alpha_window.o
openmp_matrix: openmp_matrix.o
sdl_v4l_video: sdl_v4l_video.o
view_sizes: view_sizes.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
