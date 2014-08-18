include ../../Makefile-flags.windows

all: dll_thread.dll test_dll_thread.exe

clean:
	rm -f lib*.a *.dll *.exe *.o

# Either "dll_thread.dll" or "-L. -ldll_thread" are available to the linker
test_dll_thread.exe: test_dll_thread.o dll_thread.dll
	$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.dll: %.o
	$(WINCC) $(LDFLAGS) -shared -o $@ $^ -Wl,--subsystem=0,--out-implib,lib$*.a

dll_thread.o: CPPFLAGS += -DBUILDING_DLL
%.o: %.c dll_thread.h
	$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
