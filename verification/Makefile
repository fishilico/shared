CC ?= cc
# Use FRAMAC=frama-c-gui to use the gui
FRAMAC ?= frama-c

CPPFLAGS ?= -D_FORTIFY_SOURCE=2
CFLAGS ?= -O2 -Wall -W -Wextra -ansi -pedantic -pipe \
	-Wmissing-prototypes -Wno-unused-function -Wformat=2 -Wpointer-arith \
	-Winit-self -Wwrite-strings -Wno-shadow \
	-fno-exceptions -fno-stack-protector -fvisibility=hidden -fPIE
LDFLAGS ?= -Wl,-z,relro,-z,now,--no-undefined -fPIE -pie

# Use Frama-C libc headers which contains ACSL annotations.
FRAMAC_SHARE_PATH := $(shell frama-c -print-share-path)
FRAMAC_CFLAGS := -nostdinc -I$(FRAMAC_SHARE_PATH)/libc

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
OBJECTS :=

OBJECTS := $(SOURCES:%.c=%.o)
BINARIES := $(OBJECTS:%.o=%.out)
FRAMAC_SESSIONS := $(SOURCES:%.c=%.sav)

# Compile things only if windows.h can be included
ifeq ($(shell $(FRAMAC) --version > /dev/null 2>&1 && echo y),y)
all: $(BINARIES) $(FRAMAC_SESSIONS)
else
all: $(BINARIES)
	@echo "Skip verification as $(FRAMAC) does not exist."
endif

clean:
	rm -f *.o *.out *.i
	rm -rf tmp

%.out: %.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

%.sav: %.c
	[ -d tmp ] || mkdir tmp
	@# Examples of Frama-C parameters:
	@# - Value: -val -slevel 3
	@# - Weakest precondition: -wp -wp-rte -wp-model Typed+cast -wp-timeout 5 -wp-split -wp-out tmp
	@# - Jessie: -jessie -jessie-atp=simplify -jessie-infer-annot pre
	$(FRAMAC) -cpp-extra-args='$(FRAMAC_CFLAGS)' -save $@ \
		-pp-annot -no-unicode \
		-wp -wp-rte -wp-model Typed+cast -wp-timeout 5 -wp-split -wp-out tmp $<

.PHONY: all clean
