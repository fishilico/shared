include ../../windows-flags.mk

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
BINARIES := $(SOURCES:%.c=%.exe)

all: $(BINARIES)

clean:
	rm -f *.exe *.o

helloworld_noimport.exe: LDFLAGS += -Wl,--subsystem=windows
helloworld_noimport.exe: LDFLAGS += -nostdlib -Wl,--nostdlib
helloworld_noimport.o: CFLAGS += -nostdlib -fno-stack-protector

%.exe: %.o
	$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c $(HEADERS)
	$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<
