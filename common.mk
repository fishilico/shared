# Makefile definitions which are common to every projects

# External commands used in this file
GREP ?= grep
PKG_CONFIG ?= pkg-config
PYTHON ?= python
PYTHON3 ?= python3
RM ?= rm -f
SH ?= sh

# Python linters
FLAKE8 ?= flake8
PYLINT ?= pylint

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
V_PANDOC    = @echo '  PANDOC    $<';
V_PDFLATEX  = @echo '  PDFLATEX  $<';
V_WINCC     = @echo '  WINCC     $<';
V_WINCCLD   = @echo '  WINCCLD   $@';

V_CLEAN     = @echo '  CLEAN';
endif
endif

# Clean command
CLEAN_CMD := $(V_CLEAN)$(RM) \
	*.a *.aux *.bin *.dll *.efi *.elf *.exe *.glob *.log *.o *.out *.pdf \
	*.rst.tex *.so *.tmp *.toc *.vo .*.d .*.o && \
	$(RM) -r __pycache__

# Try running a command and output the second or third parameter accordingly.
# The implementation of this function was copied from Linux (file scripts/Kbuild.include)
try-run = $(shell set -e; if ($(1)) >/dev/null 2>&1; then echo "$(2)"; else echo "$(3)"; fi)

# Try running the command, with a temporary file given as first parameter
try-run-with-tmp = $(shell set -e; if ($(2)) >/dev/null 2>&1; then echo "$(3)"; else echo "$(4)"; fi; $(RM) "$(1)")

# Output "y" if the specified command can be run
can-run = $(call try-run,$(1),y,n)
can-run-with-tmp = $(call try-run-with-tmp,$(1),$(2),y,n)

# Test a C Compiler PreProcessor option
ccpp-has-option = $(call can-run,$(CC) -Werror $(1) -E - < /dev/null)
ccpp-option = $(call try-run,$(CC) -Werror $(1) -E - < /dev/null,$(1),$(2))
cc-disable-warning = $(call try-run,$(CC) -Werror -W$(strip $(1)) -E - < /dev/null,-Wno-$(strip $(1)))

# Test a C Compiler and linker option
# Run the test program to detect linker bugs,
# for example to detect broken 'musl-gcc -fsanitize=undefined'
ccld-has-option = $(call can-run-with-tmp,.$$$$.tmp,echo "int main(void){return 0;}" |$(CC) -Werror -x c -o".$$$$.tmp" $(1) - && ./.$$$$.tmp)

# Test whether a pkg-config package exists and an include file is found (with -include option)
pkg-config-with-options = $(call ccld-has-option,$(shell $(PKG_CONFIG) --cflags --libs $(1) 2>/dev/null) $(2))

# Run a command with an optional prefix to perform runtime tests.
# The prefix would be "wine" for Windows applications on Linux, "qemu-arm" for
# ARM programs on x86, etc.
# Add a special case for Python and Shell programs
RUN_TEST_PREFIX ?=
run-test-progs = \
	for P in $(sort $(1)); do \
		if [ "$${P%.py}" != "$$P" ] ; then \
			echo "$(PYTHON) ./$$P" && \
			$(PYTHON) "./$$P" || exit $$? ; \
		elif [ "$${P%.py3}" != "$$P" ] ; then \
			echo "$(PYTHON) ./$$P" && \
			$(PYTHON) "./$$P" || exit $$? ; \
		elif [ "$${P%.sh}" != "$$P" ] ; then \
			echo "$(SH) ./$$P" && \
			$(SH) "./$$P" || exit $$? ; \
		else \
			echo $(RUN_TEST_PREFIX) "./$$P" && \
			$(RUN_TEST_PREFIX) "./$$P" || exit $$? ; \
		fi ; \
	done

# Get the target architecture of the compiler
# Usage: TARGET_TRIPLET := $(get-cc-target-triplet)
get-cc-target-triplet = $(shell $(CC) -dumpmachine)

# "gcc -m32 -dumpmachine" prints x86_64-unknown-linux-gnu on x86_64, not i386, which forces this selection
select_x86_bits = $(shell printf '\#ifdef __x86_64__\nx86_64\n\#elif defined(__i386__)\nx86_32\n\#endif' |$(CC) -E - |$(GREP) '^x86')

# Usage: TARGET_ARCH := $(call cc-triplet2arch,$(TARGET_TRIPLET))
cc-triplet2arch = \
$(or \
$(if $(filter aarch64%,$(1)),arm64), \
$(if $(filter arm%,$(1)),arm), \
$(if $(filter i386-%,$(1)),x86_32), \
$(if $(filter i486-%,$(1)),x86_32), \
$(if $(filter i686-%,$(1)),x86_32), \
$(if $(filter x86_64-%,$(1)),$(select_x86_bits)), \
)
# Get the target architecture when the target OS is not needed
get-cc-target-arch = $(call cc-triplet2arch,$(get-cc-target-triplet))

# Usage: TARGET_OS := $(call cc-triplet2os,$(TARGET_TRIPLET))
cc-triplet2os = \
$(or \
$(if $(findstring -linux, $(1)),linux), \
$(if $(findstring -mingw, $(1)),windows), \
)
