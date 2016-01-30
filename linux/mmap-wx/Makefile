include ../../linux-flags.mk

SOURCES := $(wildcard *.c)
BINARIES := $(SOURCES:%.c=%.$(BIN_EXT))

all: $(BINARIES)
	@:

clean:
	$(CLEAN_CMD)

test: all
	@$(call run-test-progs,$(BINARIES))

%.$(BIN_EXT): .%.o
	$(V_CCLD)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

.%.o: %.c
	$(V_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean test
.PRECIOUS: .%.o

-include .*.d
