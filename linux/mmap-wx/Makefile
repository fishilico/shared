include ../../linux-flags.mk

# Use Linux >=3.11 O_TMPFILE feature, if available
CPPFLAGS += -DO_TMPFILE=020200000

SOURCES := $(wildcard *.c)
BINARIES := $(SOURCES:%.c=%.$(BIN_EXT))

all: $(BINARIES)

clean:
	rm -f *.bin *.o

%.$(BIN_EXT): %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $^

.PHONY: all clean
