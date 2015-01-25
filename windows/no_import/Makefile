include ../../windows-flags.mk

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
BINARIES := $(SOURCES:%.c=%.$(BIN_EXT))

all: $(BINARIES)

clean:
	rm -f *.exe *.o

test: all

helloworld_noimport.$(BIN_EXT): LDFLAGS += -Wl,--subsystem=windows
helloworld_noimport.$(BIN_EXT): LDFLAGS += -nostdlib -Wl,--nostdlib
helloworld_noimport.o: CFLAGS += -nostdlib -fno-stack-protector

%.$(BIN_EXT): %.o
	$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c $(HEADERS)
	$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean test
