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

ifneq ($(CC), clang)
BINARIES += openmp_matrix
endif

HAS_GTK3 := $(shell pkg-config --exists gtk+-3.0 && echo 'y' || echo 'n')
ifeq ($(HAS_GTK3), y)
	BINARIES += gtk_alpha_window
	GTK_LDFLAGS := $(shell pkg-config --libs gtk+-3.0)
	GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0)
else
	HAS_GTK2 := $(shell pkg-config --exists gtk+-2.0 && echo 'y' || echo 'n')
	ifeq ($(HAS_GTK2), y)
		BINARIES += gtk_alpha_window
		GTK_LDFLAGS := $(shell pkg-config --libs gtk+-2.0)
		GTK_CFLAGS := $(shell pkg-config --cflags gtk+-2.0)
	endif
endif

all: $(BINARIES)

clean:
	rm -f *.o
	rm -f $(BINARIES)

cpuid: cpuid.o
	$(CC) $(LDFLAGS) -o $@ $^

gtk_alpha_window: LDFLAGS += $(GTK_LDFLAGS)
gtk_alpha_window.o: CFLAGS += $(GTK_CFLAGS)
gtk_alpha_window: gtk_alpha_window.o
	$(CC) $(LDFLAGS) -o $@ $^

openmp_matrix: openmp_matrix.o
	$(CC) $(LDFLAGS) -fopenmp -o $@ $^

openmp_matrix.o: CFLAGS += -fopenmp

view_sizes: view_sizes.o
	$(CC) $(LDFLAGS) -o $@ $^

view_sizes.o: CFLAGS += -Wno-long-long

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
