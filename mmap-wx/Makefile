CC ?= gcc
CFLAGS ?= -Wall -W -Wextra -O2 -pipe -fstack-protector -D_FORTIFY_SOURCE=2 -ansi -fPIE

all: mmap-wx

mmap-wx: mmap-wx.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: all
