include ../os-detect.mk

PYTHON ?= python
PYTHON3 ?= python3
PEP8 ?= pep8
PYLINT ?= pylint

# Programs not to test automatically
NONTEST_BINARIES := matplotlib_feed_plot3d.py unicode_norm.py

HAVE_PYTHON_CFFI := $(call can-run,$(PYTHON) -c 'import cffi')
HAVE_PYTHON_NUMPY := $(call can-run,$(PYTHON) -c 'import numpy')
HAVE_PYTHON3_SOCKET_RECVMSG := $(call can-run,$(PYTHON3) -c 'import socket;socket.socket.recvmsg')

ifneq ($(HAVE_PYTHON_CFFI),y)
NONTEST_BINARIES += cffi_example.py cffi_numpy.py
else ifneq ($(HAVE_PYTHON_NUMPY),y)
NONTEST_BINARIES += cffi_numpy.py
endif

ifneq ($(HAVE_PYTHON3_SOCKET_RECVMSG),y)
NONTEST_BINARIES += udp_multihome.py
endif

BINARIES := $(wildcard *.py)
TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(BINARIES))

# Ignore line-too-long
PEP8_PARAMS := '--ignore=E501'

PYLINT_PARAMS := '--msg-template=L{line}: {msg_id}({symbol}) {msg}'
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
	$(PEP8) $(PEP8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

list-nobuild:
	@echo $(NONTEST_BINARIES)

test: all
	@@for P in $(sort $(TEST_BINARIES)); do echo ./$$P && ./$$P || exit $$? ; done

_cffi_example.$(LIB_EXT): LDFLAGS := $(filter-out -fPIC -fPIE -pie -shared, $(LDFLAGS))
_cffi_example.$(LIB_EXT): ._cffi_example.o
	$(V_CCLD)$(CC) $(LDFLAGS) $(LIB_LDFLAGS) -o $@ $^ $(LIBS)

._cffi_example.o: CPPFLAGS += -D_CFFI_EXAMPLE_EXPORTS
._cffi_example.o: CFLAGS := $(filter-out -fPIC -fPIE, $(CFLAGS))
._cffi_example.o: _cffi_example.c
	$(V_CC)$(CC) $(CFLAGS) $(LIB_CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean lint list-nobuild test

-include .*.d
