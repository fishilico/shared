CC ?= cc
# C preprocessor flags
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
# C compiler flags
CFLAGS ?= -O2 -Wall -W -Wextra -ansi -pedantic \
	-Wmissing-prototypes -Wno-unused-function -Wformat=2 \
	-fstack-protector --param=ssp-buffer-size=4 -fPIE
# Linker flags
LDFLAGS ?= -Wl,-z,relro,-z,now -fPIE -pie

BINARIES := cpuid openmp_matrix view_sizes

all: $(BINARIES)

clean:
	rm -f *.o
	rm -f $(BINARIES)

cpuid: cpuid.o
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
