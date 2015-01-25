include ../os-detect.mk

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


all: _cffi_example.$(LIB_EXT)

clean:
	rm -f *.o *.so *.dll
	rm -rf __pycache__

lint:
	$(PEP8) $(PEP8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

test: _cffi_example.$(LIB_EXT)
	if $(PYTHON) -c 'import cffi'; then \
		$(PYTHON) cffi_example.py; \
		if $(PYTHON) -c 'import numpy'; then \
			$(PYTHON) cffi_numpy.py; \
		else \
			echo "Skip cffi-numpy tests because python-numpy is not installed"; \
		fi \
	else \
		echo "Skip cffi tests because python-cffi is not installed"; \
	fi

_cffi_example.$(LIB_EXT): _cffi_example.o
	$(CC) $(LDFLAGS) $(LIB_LDFLAGS) -o $@ $^ $(LIBS)

_cffi_example.o: CPPFLAGS += -D_CFFI_EXAMPLE_EXPORTS
_cffi_example.o: _cffi_example.c cffi_example.h
	$(CC) $(CFLAGS) $(LIB_CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean lint test
