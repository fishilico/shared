include ../../os-detect.mk

UNAME ?= uname

# Find other programs. Only programs in $(PROGRAMS) are built.
SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
PROGRAMS := $(filter-out arch_% os_% test_asm_%, $(SOURCES:%.c=%))

# Add OS- and arch-dependent object files
OBJECTS = arch_common.o
TARGET_TRIPLET := $(shell $(CC) -dumpmachine)

ifneq (,$(findstring i386, $(TARGET_TRIPLET)))
OBJECTS += arch_x86.o
else ifneq (,$(findstring i686, $(TARGET_TRIPLET)))
OBJECTS += arch_x86.o
else ifneq (,$(findstring x86_64, $(TARGET_TRIPLET)))
# "gcc -m32 -dumpmachine" prints x86_64-unknown-linux-gnu on x86_64, not i386...
OBJECTS += $(shell printf '\#ifdef __x86_64__\narch_x86_64.o\n\#else\narch_x86.o\n\#endif' |$(CC) -E - |grep '^arch')
else
OBJECTS += arch_unknown.o
endif

ifneq (,$(findstring arch_x86.o, $(OBJECTS)))
PROGRAMS += test_asm_x86
else ifneq (,$(findstring arch_x86_64.o, $(OBJECTS)))
PROGRAMS += test_asm_x86_64
endif

ifneq (,$(findstring -linux, $(TARGET_TRIPLET)))
OBJECTS += os_linux.o
else ifneq (,$(findstring -mingw, $(TARGET_TRIPLET)))
OBJECTS += os_windows.o
else
OBJECTS += os_unknown.o
endif

BINARIES := $(PROGRAMS:%=%.$(BIN_EXT))

all: $(BINARIES)

clean:
	rm -f *.o *.bin *.exe

debug: CPPFLAGS += -DDEBUG=1
debug: all

test: all
	@for P in $(sort $(BINARIES)); do echo ./$$P && ./$$P || exit $$? ; done

%.$(BIN_EXT): %.o $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Disable strict-aliasing warning for XMM sub-part tests
test_%.o: CFLAGS += -Wno-strict-aliasing

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

arch_unknown.o:
	@echo "Unknown architecture from triplet $(TARGET_TRIPLET)"
	@false

os_unknown.o:
	@echo "Unknown OS from triplet $(TARGET_TRIPLET)"
	@false

.PHONY: all clean debug test
.PRECIOUS: %.o
