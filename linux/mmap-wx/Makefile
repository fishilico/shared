include ../../Makefile-flags.linux

# Be pedantic, because we can!
CFLAGS += -pedantic

# Use Linux >=3.11 O_TMPFILE feature, if available
CPPFLAGS += -DO_TMPFILE=020200000

all: mmap-wx.bin mmap-wx-simple.bin

clean:
	rm -f *.bin *.o

%.bin: %.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $^

.PHONY: all clean
