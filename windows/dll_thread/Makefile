include ../../windows-flags.mk

all: dll_thread.$(LIB_EXT) test_dll_thread.$(BIN_EXT)
	@:

clean:
	$(CLEAN_CMD)

test: all
	$(SLEEP_AFTER_WINE_IF_NEEDED)
	@$(call run-test-progs,test_dll_thread.$(BIN_EXT))
	$(SLEEP_AFTER_WINE_IF_NEEDED)

# Either "dll_thread.dll" or "-L. -ldll_thread" are available to the linker
test_dll_thread.$(BIN_EXT): .test_dll_thread.o dll_thread.$(LIB_EXT)
	$(V_WINCCLD)$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.$(LIB_EXT): .%.o
	$(V_WINCCLD)$(WINCC) $(LDFLAGS) -shared -o $@ $^ -Wl,--subsystem=0,--out-implib,lib$*.a

.dll_thread.o: CPPFLAGS += -DBUILDING_DLL
.%.o: %.c
	$(V_WINCC)$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean test
.PRECIOUS: .%.o

-include .*.d
