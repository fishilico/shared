include ../windows-flags.mk

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
BINARIES := $(SOURCES:%.c=%.$(BIN_EXT))

all: $(BINARIES)

clean:
	rm -f *.exe *.o

# Don't run any program in "make test" as it may require wine or wine64 depending on the distro
test: all

check_winmain_params.$(BIN_EXT) helloworld.$(BIN_EXT): LDFLAGS += -Wl,--subsystem=windows
list_processes.$(BIN_EXT) virtual_mem.$(BIN_EXT): LIBS += -lpsapi
network_stat.$(BIN_EXT): LIBS += -liphlpapi -lws2_32
uuidgen.$(BIN_EXT): LIBS += -lrpcrt4

%.$(BIN_EXT): %.o
	$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c $(HEADERS)
	$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean test
