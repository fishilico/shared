include ../../env-python.mk

NEVER_TEST_BINARIES := github_repos.py gitlab_projects.py parse_tcp_stream.py pcap_netmap.py resolve_domains.py web_api.py
NONTEST_BINARIES := $(NEVER_TEST_BINARIES)

HAVE_PYTHON_SOCKET_RECVMSG := $(call can-run,$(PYTHON) -c 'import socket;socket.socket.recvmsg')

ifneq ($(HAVE_PYTHON_SOCKET_RECVMSG),y)
NONTEST_BINARIES += udp_multihome.py
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
