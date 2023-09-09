include ../env-python.mk

# Python's pathlib module was introduced in Python 3.4
HAVE_PYTHON_PATHLIB := $(call can-run,$(PYTHON) -c 'import pathlib')

all:
	@:

clean:
	$(CLEAN_CMD)

lint:
	$(FLAKE8) $(FLAKE8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

# Download GnuPG keys
sync-inet:
	$(SH) ./send_often_missing_keys.sh
	$(SH) ./send_often_missing_keys.sh
	$(SH) ./send_often_missing_keys.sh
	$(PYTHON) ./sync_keys.py

test: all
	@:

.PHONY: all clean lint sync-inet test
