include ../os-detect.mk
include ../env-python.mk

# Programs not to test automatically
NEVER_TEST_BINARIES := image_lsb.py matplotlib_feed_plot3d.py svndump_extract.py unicode_norm.py
NONTEST_BINARIES := $(NEVER_TEST_BINARIES)

HAVE_PYTHON_CFFI := $(call can-run,$(PYTHON) -c 'import cffi')
HAVE_PYTHON_NUMPY := $(call can-run,$(PYTHON) -c 'import numpy')
HAVE_PYTHON_Z3 := $(call can-run,$(PYTHON) -c 'import z3;z3.BitVec')

HAVE_PYTHON_FSTRING := $(call can-run,$(PYTHON) -c 'f""')

# On Windows, open("/etc/shells") fails, and this is required to test xml_xxe_file.py
HAVE_PYTHON_OPEN_ETC_SHELLS := $(call can-run,$(PYTHON) -c 'open("/etc/shells", "rb")')

ifneq ($(HAVE_PYTHON_CFFI),y)
NONTEST_BINARIES += cffi_example.py cffi_numpy.py
else ifneq ($(HAVE_PYTHON_NUMPY),y)
NONTEST_BINARIES += cffi_numpy.py
endif

ifneq ($(HAVE_PYTHON_Z3),y)
NONTEST_BINARIES += z3_example.py
endif

ifneq ($(HAVE_PYTHON_FSTRING),y)
NONTEST_BINARIES += clang_cfi_typeid.py
endif

ifneq ($(HAVE_PYTHON_OPEN_ETC_SHELLS),y)
NONTEST_BINARIES += xml_xxe_file.py
endif

BINARIES := $(wildcard *.py)
TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(BINARIES))

# Disable too-many-instance-attributes, too-many-arguments
PYLINT_PARAMS += --disable=R0902,R0913
# Disable invalid-name, superfluous-parens
PYLINT_PARAMS += --disable=C0103,C0325
# Disable no-member, maybe-no-member
PYLINT_PARAMS += --disable=E1101,E1103
# Disable import-error
PYLINT_PARAMS += --disable=F0401


all: _cffi_example.$(LIB_EXT)
	@:

clean:
	$(CLEAN_CMD)

lint:
	$(FLAKE8) $(FLAKE8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

# Do not report scripts which have no chance to being tested in list-nobuild
list-nobuild:
	@echo $(sort $(filter-out $(NEVER_TEST_BINARIES), $(NONTEST_BINARIES)))

test: all
	@$(call run-test-progs,$(TEST_BINARIES))

_cffi_example.$(LIB_EXT): LDFLAGS := $(filter-out -fPIC -fPIE -pie -shared, $(LDFLAGS))
_cffi_example.$(LIB_EXT): ._cffi_example.o
	$(V_CCLD)$(CC) $(LDFLAGS) $(LIB_LDFLAGS) -o $@ $^ $(LIBS)

._cffi_example.o: CPPFLAGS += -D_CFFI_EXAMPLE_EXPORTS
._cffi_example.o: CFLAGS := $(filter-out -fPIC -fPIE, $(CFLAGS))
._cffi_example.o: _cffi_example.c
	$(V_CC)$(CC) $(CFLAGS) $(LIB_CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean lint list-nobuild test

-include .*.d
