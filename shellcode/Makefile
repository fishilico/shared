include ../os-detect.mk

CHMOD ?= chmod
GREP ?= grep
OBJCOPY ?= objcopy
OBJDUMP ?= objdump
PYTHON ?= python
UNAME ?= uname

# Find the system identifier to use
TARGET_TRIPLET := $(shell $(CC) -dumpmachine)

ifneq (,$(findstring -linux, $(TARGET_TRIPLET)))
TARGET_OS := linux
else ifneq (,$(findstring -mingw, $(TARGET_TRIPLET)))
TARGET_OS := windows
else
TARGET_OS := unknown-OS
endif

ifneq (,$(filter arm%, $(TARGET_TRIPLET)))
TARGET_ARCH := arm
else ifneq (,$(filter i386-%, $(TARGET_TRIPLET)))
TARGET_ARCH := x86_32
else ifneq (,$(filter i486-%, $(TARGET_TRIPLET)))
TARGET_ARCH := x86_32
else ifneq (,$(filter i686-%, $(TARGET_TRIPLET)))
TARGET_ARCH := x86_32
else ifneq (,$(filter x86_64-%, $(TARGET_TRIPLET)))
# "gcc -m32 -dumpmachine" prints x86_64-unknown-linux-gnu on x86_64, not i386...
TARGET_ARCH := $(shell printf '\#ifdef __x86_64__\nx86_64\n\#else\nx86_32\n\#endif' |$(CC) -E - |$(GREP) '^x86')
else
TARGET_ARCH := unknown-arch
endif

SHELLCODE_NAME := $(TARGET_OS)_$(TARGET_ARCH)
SHELLCODE_BIN := $(SHELLCODE_NAME).$(BIN_EXT)
SHELLCODE_RAW := $(SHELLCODE_NAME).raw.out

all: $(SHELLCODE_RAW)
	@:

clean:
	$(CLEAN_CMD)

test: all
	@for P in $(sort $(wildcard *.py)); do \
		echo ./$$P && $(PYTHON) ./$$P || exit $$? ; \
	done

# Dump of the shellcode
shcdump: $(SHELLCODE_RAW) $(SHELLCODE_BIN)
	$(PYTHON) -c 'print(open("$(SHELLCODE_RAW)", "rb").read())'
	$(OBJDUMP) -d $(SHELLCODE_BIN)

$(SHELLCODE_RAW): $(SHELLCODE_BIN)
	$(V_OBJCOPY)$(OBJCOPY) -j .shcode -O binary $< $@ && $(CHMOD) -x $@

$(SHELLCODE_BIN): LDFLAGS += -nostdlib
%.$(BIN_EXT): .%.o
	$(V_CCLD)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

.%.o: %.S
	$(V_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean test shcdump
.PRECIOUS: .%.o
