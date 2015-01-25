include ../../windows-flags.mk

all: dll_thread.$(LIB_EXT) test_dll_thread.$(BIN_EXT)

clean:
	rm -f lib*.a *.dll *.exe *.o

# Either "dll_thread.dll" or "-L. -ldll_thread" are available to the linker
test_dll_thread.$(BIN_EXT): test_dll_thread.o dll_thread.$(LIB_EXT)
	$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.$(LIB_EXT): %.o
	$(WINCC) $(LDFLAGS) -shared -o $@ $^ -Wl,--subsystem=0,--out-implib,lib$*.a

dll_thread.o: CPPFLAGS += -DBUILDING_DLL
%.o: %.c dll_thread.h
	$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
