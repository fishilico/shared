CC ?= gcc
# C preprocessor flags
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
# C compiler flags
CFLAGS ?= -O2 -Wall -W -Wextra -Wformat=2 -ansi -pedantic \
	-pipe -fstack-protector --param=ssp-buffer-size=4 -fPIE
# Linker flags
LDFLAGS ?= -Wl,-z,relro,-z,now -pie

# Use Linux >=3.11 O_TMPFILE feature, if available
CPPFLAGS += -DO_TMPFILE=020200000

all: mmap-wx mmap-wx-simple

clean:
	rm -f *.o
	rm -f mmap-wx mmap-wx-simple

mmap-wx: mmap-wx.o
	$(CC) $(LDFLAGS) -o $@ $^

mmap-wx-simple: mmap-wx-simple.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $^

.PHONY: all clean
