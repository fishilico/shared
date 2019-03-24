include ../../env-python.mk

NEVER_TEST_BINARIES := image_lsb.py matplotlib_feed_plot3d.py pcap_netmap.py unicode_norm.py
NONTEST_BINARIES := $(NEVER_TEST_BINARIES)

HAVE_PYTHON_CRYPTO := $(call can-run,$(PYTHON) -c 'import Crypto')

ifneq ($(HAVE_PYTHON_CRYPTO),y)
NONTEST_BINARIES += parse_jceks.py parse_pkcs12.py util_asn1.py
endif

JAVA_SOURCES := $(wildcard *.java)
JAVA_CLASSES := $(JAVA_SOURCES:%.java=%.class)

PYTHON_SCRIPTS := $(wildcard *.py)
TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(PYTHON_SCRIPTS))


all: $(JAVA_CLASSES)
	@:

clean:
	$(CLEAN_CMD)

lint:
	$(FLAKE8) $(FLAKE8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

list-nobuild:
	@echo $(sort $(filter-out $(NEVER_TEST_BINARIES), $(NONTEST_BINARIES)))

test: all
	@$(call run-test-progs,$(TEST_BINARIES))


%.class: %.java
	$(V_JAVAC)$(JAVAC) $<

.PHONY: all clean lint list-nobuild test
