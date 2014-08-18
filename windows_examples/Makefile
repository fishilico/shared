include ../Makefile-flags.windows

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
BINARIES := $(SOURCES:%.c=%.exe)

SUBMAKEFILES := $(wildcard */Makefile)
SUBDIRS := $(SUBMAKEFILES:%/Makefile=%)
ALL_TARGETS := $(addprefix all.., $(SUBDIRS))
CLEAN_TARGETS := $(addprefix clean.., $(SUBDIRS))

# Compile things only if windows.h can be included
ifeq ($(shell $(WINCC) -E helloworld.c > /dev/null 2>&1 && echo y),y)
all: $(BINARIES) $(ALL_TARGETS)
else
all:
	@echo "Skip compilation as $(WINCC) can't compile helloworld.c."
endif

all..%:
	$(MAKE) -C $* all

clean: $(CLEAN_TARGETS)
	rm -f *.exe *.o

clean..%:
	$(MAKE) -C $* clean

check_winmain_params.exe helloworld.exe helloworld_noimport.exe: LDFLAGS += -Wl,--subsystem=windows
helloworld_noimport.exe: LDFLAGS += -nostdlib -Wl,--nostdlib
helloworld_noimport.o: CFLAGS += -nostdlib -fno-stack-protector
list_processes.exe: LIBS += -lpsapi
uuidgen.exe: LIBS += -lrpcrt4

%.exe: %.o
	$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c $(HEADERS)
	$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all all..% clean clean..%
