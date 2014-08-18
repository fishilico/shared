include ../Makefile-flags.linux

PYTHON ?= python
PEP8 ?= pep8
PYLINT ?= pylint

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


all: _cffi_example.so

clean:
	rm -f *.o *.so
	rm -rf __pycache__

lint:
	$(PEP8) $(PEP8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

test: _cffi_example.so
	$(PYTHON) cffi_example.py
	$(PYTHON) cffi_numpy.py

_cffi_example.so: CPPFLAGS += -D_CFFI_EXAMPLE_EXPORTS
_cffi_example.so: CFLAGS += -fPIC
_cffi_example.so: LDFLAGS += -fPIC -shared -Wl,-soname,$@
_cffi_example.so: _cffi_example.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

_cffi_example.o: _cffi_example.c cffi_example.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean lint test
