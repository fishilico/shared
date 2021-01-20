include ../../env-python.mk

NEVER_TEST_BINARIES := docker_image.py github_repos.py gitlab_projects.py parse_tcp_stream.py pcap_netmap.py resolve_domains.py web_api.py
NONTEST_BINARIES := $(NEVER_TEST_BINARIES)

HAVE_PYTHON_SOCKET_RECVMSG := $(call can-run,$(PYTHON) -c 'import socket;socket.socket.recvmsg')
HAVE_PYTHON_NOT_OS_NAME_NT := $(call can-run,$(PYTHON) -c 'import os;assert os.name != "nt"')

ifneq ($(HAVE_PYTHON_SOCKET_RECVMSG),y)
NONTEST_BINARIES += udp_multihome.py
endif

# Skip getifaddrs_ctypes on Windows (this script is specific to Linux).
ifneq ($(HAVE_PYTHON_NOT_OS_NAME_NT),y)
NONTEST_BINARIES += getifaddrs_ctypes.py
endif

BINARIES := $(wildcard *.py)
TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(BINARIES))

all:
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

.PHONY: all clean lint list-nobuild test

-include .*.d
