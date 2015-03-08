include ../../windows-flags.mk

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
BINARIES := $(SOURCES:%.c=%.$(BIN_EXT))

NOIMPORT_PROGRAMS := $(filter-out check_%, $(SOURCES:%.c=%))

all: $(BINARIES)

clean:
	$(CLEAN_CMD)

test: all

$(NOIMPORT_PROGRAMS:%=%.$(BIN_EXT)): LDFLAGS += -Wl,--subsystem=windows
$(NOIMPORT_PROGRAMS:%=%.$(BIN_EXT)): LDFLAGS += -nostdlib -Wl,--nostdlib
$(NOIMPORT_PROGRAMS:%=.%.o): CFLAGS += -nostdlib -fno-stack-protector

%.$(BIN_EXT): .%.o
	$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

.%.o: %.c $(HEADERS)
	$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean test
.PRECIOUS: .%.o
