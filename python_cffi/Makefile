CC ?= gcc
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
CFLAGS ?= -g -pipe -O2 -ansi -pedantic \
	-Wall -W -Wextra -Wformat=2 -Wpointer-arith -Winit-self \
	-Wwrite-strings -Wshadow \
	-fstack-protector --param=ssp-buffer-size=4 \
	-fno-exceptions -fvisibility=internal
LDFLAGS ?= -Wl,-z,relro,-z,now,--no-undefined

PYTHON ?= python
PEP8 ?= pep8
PYLINT ?= pylint

PYLINT_PARAMS := '--msg-template=L{line}: {msg_id}({symbol}) {msg}'
# Disable invalid-name, superfluous-parens
PYLINT_PARAMS += --disable=C0103,C0325
# Disable no-member
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
	$(PYTHON) cffi_numpy.py

_cffi_example.so: CPPFLAGS += -D_CFFI_EXAMPLE_EXPORTS
_cffi_example.so: CFLAGS += -fPIC -shared
_cffi_example.so: LDFLAGS += -fPIC -shared -Wl,-soname,$@
_cffi_example.so: _cffi_example.o
	$(CC) $(LDFLAGS) -o $@ $^

_cffi_example.o: _cffi_example.c cffi_example.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean lint test
