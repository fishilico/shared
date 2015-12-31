include ../windows-flags.mk

NONTEST_PROGRAMS := check_winmain_params console_attr helloworld

SOURCES := $(wildcard *.c)
BINARIES := $(SOURCES:%.c=%.$(BIN_EXT))
TEST_BINARIES := $(filter-out $(NONTEST_PROGRAMS:%=%.$(BIN_EXT)), $(BINARIES))

all: $(BINARIES)
	@:

clean:
	$(CLEAN_CMD)

test: all
	@$(call run-test-progs,$(TEST_BINARIES))

check_winmain_params.$(BIN_EXT) helloworld.$(BIN_EXT): LDFLAGS += -Wl,--subsystem=windows
list_processes.$(BIN_EXT) virtual_mem.$(BIN_EXT): LIBS += -lpsapi
network_stat.$(BIN_EXT): LIBS += -liphlpapi -lws2_32
uuidgen.$(BIN_EXT): LIBS += -lrpcrt4
wmi_query.$(BIN_EXT): LIBS += -lole32 -loleaut32

%.$(BIN_EXT): .%.o
	$(V_WINCCLD)$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

.%.o: %.c
	$(V_WINCC)$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean test
.PRECIOUS: .%.o

-include .*.d
