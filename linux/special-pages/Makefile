include ../../linux-flags.mk

SOURCES := $(wildcard *.c)
PROGRAMS := $(SOURCES:%.c=%)

all: $(PROGRAMS:%=%.bin)

clean:
	rm -f *.bin *.o *.out *.so

%.bin: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
