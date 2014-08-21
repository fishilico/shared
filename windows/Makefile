include ../windows-flags.mk

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
BINARIES := $(SOURCES:%.c=%.exe)

all: $(BINARIES)

clean:
	rm -f *.exe *.o

check_winmain_params.exe helloworld.exe: LDFLAGS += -Wl,--subsystem=windows
list_processes.exe: LIBS += -lpsapi
network_stat.exe: LIBS += -liphlpapi -lws2_32
uuidgen.exe: LIBS += -lrpcrt4

%.exe: %.o
	$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c $(HEADERS)
	$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
