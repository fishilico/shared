include ../../linux-flags.mk

# Don't test vdso extraction in "make test" as some architecture doesn't provide it
NONTEST_BINARIES := extract_vdso.py

SOURCES := $(wildcard *.c)
BINARIES := $(SOURCES:%.c=%.$(BIN_EXT))
TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(BINARIES) $(wildcard *.py))

all: $(BINARIES)
	@:

clean:
	$(CLEAN_CMD)

test: all
	@$(call run-test-progs,$(TEST_BINARIES))

%.$(BIN_EXT): .%.o
	$(V_CCLD)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

.%.o: %.c
	$(V_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean test
.PRECIOUS: .%.o

-include .*.d
