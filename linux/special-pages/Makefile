include ../../linux-flags.mk

# Don't test vdso extraction in "make test" as some architecture doesn't provide it
NONTEST_BINARIES := extract_vdso.py

SOURCES := $(wildcard *.c)
BINARIES := $(SOURCES:%.c=%.$(BIN_EXT))
TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(BINARIES) $(wildcard *.py))

all: $(BINARIES)

clean:
	rm -f *.bin *.o *.out *.so

test: all
	@for P in $(sort $(TEST_BINARIES)); do echo ./$$P && ./$$P || exit $$? ; done

%.$(BIN_EXT): %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean test
