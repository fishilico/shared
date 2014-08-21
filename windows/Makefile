include ../windows-flags.mk

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

check_winmain_params.exe helloworld.exe: LDFLAGS += -Wl,--subsystem=windows
list_processes.exe: LIBS += -lpsapi
network_stat.exe: LIBS += -liphlpapi -lws2_32
uuidgen.exe: LIBS += -lrpcrt4

%.exe: %.o
	$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c $(HEADERS)
	$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all all..% clean clean..%
