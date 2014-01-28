CC ?= gcc
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
CFLAGS ?= -g -O2 -Wall -W -Wextra -Wformat=2 -pipe -fstack-protector --param=ssp-buffer-size=4 -ansi -pedantic
LDFLAGS ?= -Wl,-z,relro,-z,now

PYTHON ?= python
PEP8 ?= pep8
PYLINT ?= pylint

PYLINT_PARAMS := --include-ids=y
# Disable "Invalid name"
PYLINT_PARAMS += --disable=C0103
# Disable "Instance of ... has no ... member"
PYLINT_PARAMS += --disable=E1101


all: _cffi_example.so

clean:
	rm -f *.o
	rm -rf __pycache__

lint:
	$(PEP8) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

test: _cffi_example.so
	$(PYTHON) cffi_example.py

_cffi_example.so: _cffi_example.o
	$(CC) $(LDFLAGS) -fPIC -shared -Wl,-soname,$@ -o $@ $^

_cffi_example.o: _cffi_example.c cffi_example.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -fPIC -shared -c -o $@ $<

.PHONY: all clean lint test
