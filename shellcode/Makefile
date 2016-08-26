include ../os-detect.mk

CHMOD ?= chmod
GREP ?= grep
OBJCOPY ?= objcopy
OBJDUMP ?= objdump
PYTHON ?= python
UNAME ?= uname

# Find the system identifier to use
TARGET_TRIPLET := $(get-cc-target-triplet)
TARGET_ARCH := $(or $(call cc-triplet2arch,$(TARGET_TRIPLET)),unknown-arch)
TARGET_OS := $(or $(call cc-triplet2os,$(TARGET_TRIPLET)),unknown-OS)

SHELLCODE_NAME := $(TARGET_OS)_$(TARGET_ARCH)
SHELLCODE_BIN := $(SHELLCODE_NAME).$(BIN_EXT)
SHELLCODE_RAW := $(SHELLCODE_NAME).raw.out

all: $(SHELLCODE_RAW)
	@:

clean:
	$(CLEAN_CMD)

test: all
	@$(call run-test-progs,$(wildcard *.py))

# Dump of the shellcode
shcdump: $(SHELLCODE_RAW) $(SHELLCODE_BIN)
	$(PYTHON) -c 'print(open("$(SHELLCODE_RAW)", "rb").read())'
	$(OBJDUMP) -d $(SHELLCODE_BIN)

$(SHELLCODE_RAW): $(SHELLCODE_BIN)
	$(V_OBJCOPY)$(OBJCOPY) -j .shcode -O binary $< $@ && $(CHMOD) -x $@

%.$(BIN_EXT): .%.o
	$(V_CCLD)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

.%.o: %.S
	$(V_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean test shcdump
.PRECIOUS: .%.o
