# Find a C compiler for windows
ifneq ($(shell mingw32-gcc --version 2> /dev/null),)
	TARGET := mingw32
else
	ARCH := $(shell uname -m)
	ifneq ($(shell $(ARCH)-w64-mingw32-gcc --version 2> /dev/null),)
		TARGET := $(ARCH)-w64-mingw32
	else
		ifneq ($(shell $(ARCH)-w32-mingw32-gcc --version 2> /dev/null),)
			TARGET := $(ARCH)-w32-mingw32
		endif
	endif
endif

ifneq ($(TARGET),)
	WINCC := $(TARGET)-gcc
else
	WINCC ?= gcc
endif
CPPFLAGS ?=
CFLAGS ?= -O2 -Wall -W -Wextra -Wformat=2 \
	-Wmissing-prototypes -Wno-unused-parameter -Wno-unused-function \
	-fno-stack-protector
LDFLAGS ?= -Wl,--enable-auto-image-base,--dynamicbase,--nxcompat

all: dll_thread.dll test_dll_thread.exe

clean:
	rm -f lib*.a *.dll *.exe *.o

# Either "dll_thread.dll" or "-L. -ldll_thread" are available to the linker
test_dll_thread.exe: test_dll_thread.o dll_thread.dll
	$(WINCC) $(LDFLAGS) -Wl,--subsystem=console -o $@ $^

%.dll: %.o
	$(WINCC) $(LDFLAGS) -shared -o $@ $^ -Wl,--subsystem=0,--out-implib,lib$*.a

dll_thread.o: CPPFLAGS += -DBUILDING_DLL
%.o: %.c dll_thread.h
	$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
