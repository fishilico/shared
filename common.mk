# Makefile definitions which are common to every projects

# Define "quiet" commands, with V=1, like git and systemd project
ifneq ($(findstring $(MAKEFLAGS), s), s)
ifndef V
V_CC        = @echo '  CC        $<';
V_CCAS      = @echo '  CCAS      $<';
V_CCLD      = @echo '  CCLD      $@';
V_COQC      = @echo '  COQC      $<';
V_FRAMAC    = @echo '  FRAMA-C   $^';
V_LD        = @echo '  LD        $@';
V_OBJCOPY   = @echo '  OBJCOPY   $@';
V_PDFLATEX  = @echo '  PDFLATEX  $<';
V_WINCC     = @echo '  WINCC     $<';
V_WINCCLD   = @echo '  WINCCLD   $@';

V_CLEAN     = @echo '  CLEAN';
endif
endif

# Clean command
RM ?= rm -f
CLEAN_CMD := $(V_CLEAN)$(RM) \
	*.a *.aux *.bin *.dll *.efi *.elf *.exe *.glob *.log *.o *.out *.pdf *.so \
	*.tmp *.toc *.vo .*.d .*.o && \
	$(RM) -r __pycache__

# Try running a command and output the second or third parameter accordingly.
# The implementation of this function was copied from Linux (file scripts/Kbuild.include)
try-run = $(shell set -e; if ($(1)) >/dev/null 2>&1; then echo "$(2)"; else echo "$(3)"; fi)

# Output "y" if the specified command can be run
can-run = $(call try-run,$(1),y,n)

# Test a C Compiler PreProcessor option
ccpp-has-option = $(call can-run,$(CC) -Werror $(1) -E - < /dev/null)
ccpp-option = $(call try-run,$(CC) -Werror $(1) -E - < /dev/null,$(1),$(2))
cc-disable-warning = $(call try-run,$(CC) -Werror -W$(strip $(1)) -E - < /dev/null,-Wno-$(strip $(1)))

# Run a command with an optional prefix to perform runtime tests.
# The prefix would be "wine" for Windows applications on Linux, "qemu-arm" for
# ARM programs on x86, etc.
# Add a special case for Python and Shell programs
PYTHON ?= python
SH ?= sh
RUN_TEST_PREFIX ?=
run-test-progs = \
	for P in $(sort $(1)); do \
		echo "./$$P" && \
		if [ "$${P%.py}" != "$$P" ] ; then \
			$(PYTHON) "./$$P" || exit $$? ; \
		elif [ "$${P%.sh}" != "$$P" ] ; then \
			$(SH) "./$$P" || exit $$? ; \
		else \
			$(RUN_TEST_PREFIX) "./$$P" || exit $$? ; \
		fi ; \
	done
