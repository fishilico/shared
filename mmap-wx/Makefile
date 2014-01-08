CC ?= gcc
CFLAGS ?= -Wall -W -Wextra -O2 -pipe -fstack-protector -D_FORTIFY_SOURCE=2 -pie -fPIE -ansi -pedantic

all: mmap-wx

mmap-wx: mmap-wx.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: all
