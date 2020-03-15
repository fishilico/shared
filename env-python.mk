# Common environment variable definitions for Python programs
include $(dir $(lastword $(MAKEFILE_LIST)))common.mk

FLAKE8_PARAMS := --max-line-length=120

MYPY_PARAMS := --disallow-any-generics --disallow-subclassing-any

PYLINT_PARAMS := '--msg-template=L{line}: {msg_id}({symbol}) {msg}'
PYLINT_PARAMS += --max-line-length=120
