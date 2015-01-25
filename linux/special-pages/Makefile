include ../../linux-flags.mk

SOURCES := $(wildcard *.c)
BINARIES := $(SOURCES:%.c=%.$(BIN_EXT))

all: $(BINARIES)

clean:
	rm -f *.bin *.o *.out *.so

%.$(BIN_EXT): %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
