CC ?= gcc
CFLAGS ?= -Wall -W -Wextra -Wformat=2 -ansi -pedantic -D_GNU_SOURCE -O2 -pipe \
    -fstack-protector --param=ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -pie -fPIE

all: mmap-wx mmap-wx-simple

clean:
	rm -f mmap-wx mmap-wx-simple

mmap-wx: mmap-wx.c
	$(CC) $(CFLAGS) -o $@ $^

mmap-wx-simple: mmap-wx-simple.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: all clean
