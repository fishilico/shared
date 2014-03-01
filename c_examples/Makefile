CC ?= cc
# C preprocessor flags
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
# C compiler flags
CFLAGS ?= -O2 -Wall -W -Wextra -ansi -pedantic \
	-Wmissing-prototypes -Wno-unused-function -Wformat=2 \
	-fstack-protector --param=ssp-buffer-size=4 -fPIE
# Linker flags
LDFLAGS ?= -Wl,-z,relro,-z,now -fPIE -pie

all: cpuid openmp_matrix

clean:
	rm -f *.o
	rm -f cpuid

cpuid: cpuid.o
	$(CC) $(LDFLAGS) -o $@ $^

openmp_matrix: openmp_matrix.o
	$(CC) $(LDFLAGS) -fopenmp -o $@ $^

openmp_matrix.o: CFLAGS += -fopenmp

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
