CC ?= cc
# C preprocessor flags
CPPFLAGS ?= -D_FORTIFY_SOURCE=2
# C compiler flags
CFLAGS ?= -O2 -Wall -W -Wextra -ansi -pedantic -pipe \
	-Wmissing-prototypes -Wno-unused-function -Wformat=2 -Wpointer-arith \
	-Winit-self -Wwrite-strings -Wno-shadow -fno-exceptions
# Linker flags
LDFLAGS ?= -Wl,-z,relro,-z,now,--no-undefined

LDFLAGS += -nostdlib -e _start

# Compile a shared object because there is no need of ld.so on Intel architecture.
# However, on ARM, all constant strings are in the GOT and ld.so fixes the
# offsets at startup when using ASLR.
GREP := grep
ifeq ($(shell $(CC) -E -v - < /dev/null 2>&1 > /dev/null | $(GREP) -qi "^Target.\s*x86" && echo y),y)
CFLAGS += -fPIC
LDFLAGS += -fPIC -shared
else
CFLAGS += -fPIE
LDFLAGS += -fPIE -pie
endif

# Files
SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
OBJECTS :=

# Compile 32-bits versions and 64-bits versions, if available
HAVE_M32_M64 ?= y
ifeq ($(shell $(CC) -m32 -E -v - < /dev/null > /dev/null 2>&1 && echo y),y)
OBJECTS += $(SOURCES:%.c=%.32.o)
else
HAVE_M32_M64 := n
endif
ifeq ($(shell $(CC) -m64 -E -v - < /dev/null > /dev/null 2>&1 && echo y),y)
OBJECTS += $(SOURCES:%.c=%.64.o)
else
HAVE_M32_M64 := n
endif
ifneq ($(HAVE_M32_M64),y)
OBJECTS := $(SOURCES:%.c=%.out.o)
endif

BINARIES := $(OBJECTS:%.o=%)

all: $(BINARIES)

all32: $(SOURCES:%.c=%.32)

all64: $(SOURCES:%.c=%.64)

clean:
	rm -f *.o
	rm -f *.out *.32 *.64

%.out: %.out.o
	$(CC) $(LDFLAGS) -o $@ $^

%.32: %.32.o
	$(CC) $(LDFLAGS) -m32 -o $@ $^

%.64: %.64.o
	$(CC) $(LDFLAGS) -m64 -o $@ $^

%.out.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

%.32.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -m32 -c -o $@ $<

%.64.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -m64 -c -o $@ $<

.PHONY: all all32 all64 clean
