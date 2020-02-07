# Define some compilation flags for Linux
#
# Debian defines hardening flags in https://wiki.debian.org/Hardening:
# * gcc -Wformat-security -Werror=format-security
# * gcc -O2 -D_FORTIFY_SOURCE=2
# * gcc -fstack-protector --param ssp-buffer-size=4
# * gcc -fPIE -pie
# * ld -z relro -z now
#
# Arch Linux defines compilation flags in /etc/makepkg.conf (from pacman)
# https://projects.archlinux.org/svntogit/packages.git/tree/trunk/makepkg.conf?h=packages/pacman
# * -D_FORTIFY_SOURCE=2
# * -mtune=generic -O2 -pipe -fstack-protector-strong --param=ssp-buffer-size=4
# * -Wl,-O1,--sort-common,--as-needed,-z,relro

include $(dir $(lastword $(MAKEFILE_LIST)))common.mk

# Centralize the choice of C compiler here (gcc, clang...)
CC ?= cc

# C preprocessor flags
# Gentoo Hardened already defines _FORTIFY_SOURCE in the compiler and warns
# about possible redefinition, so detect these warnings.
# Generate dependencies files targeting $@ in a .$@.d file
# ... while allowing using CPPFLAGS outside of a target (where $@ is empty)
CPPFLAGS = $(call ccpp-option,-D_FORTIFY_SOURCE=2) $(@:%=-Wp,-MT,$@ -Wp,-MD,$(dir $@).$(notdir $@).d)

# C compiler flags
# list of warnings from https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
CFLAGS = -O2 -ansi -pedantic -pipe \
	-Wall -Wextra \
	-Waggregate-return \
	-Wcast-align \
	-Wfloat-equal \
	-Wformat=2 \
	-Winit-self \
	-Winline \
	-Wmissing-declarations \
	-Wmissing-format-attribute \
	-Wmissing-include-dirs \
	-Wmissing-prototypes \
	-Wnested-externs \
	-Wold-style-definition \
	-Wpointer-arith \
	-Wredundant-decls \
	-Wshadow \
	-Wstrict-prototypes \
	-Wunknown-pragmas \
	-Wwrite-strings \
	-Wno-long-long \
	-Wno-unused-function \
	-fPIE \
	-fno-common \
	-fno-exceptions \
	-fstack-protector --param=ssp-buffer-size=4 \
	-fvisibility=hidden

# Linker flags
LDFLAGS = -Wl,-O1,-as-needed,-no-undefined,-z,relro,-z,now,--fatal-warnings \
	-fPIE -pie -fstack-protector

# Uncomment the next line to enable debug
#CFLAGS += -g -fvar-tracking-assignments -fno-omit-frame-pointer

# Add strong stack protector if supported
CFLAGS += $(call ccpp-option,-fstack-protector-strong)

# Disable lazy binding (from gcc 6 and clang 6)
CFLAGS += $(call ccpp-option,-fno-plt)

LIBS =

# Add clang-specific options unknown to GCC
ifeq ($(call ccpp-has-option,-Weverything), y)
	CFLAGS += -Weverything \
		-Wno-padded \
		-Wno-shift-sign-overflow \
		-Wno-unused-macros
	# added after clang 3.0
	CFLAGS += $(call cc-disable-warning,disabled-macro-expansion)
	CFLAGS += $(call cc-disable-warning,documentation)
	# clang 3.6 added -Wreserved-id-macro, which is incompatible with _GNU_SOURCE definition
	CFLAGS += $(call cc-disable-warning,reserved-id-macro)
	# clang 3.7 added -Wdocumentation-unknown-command and -fcatch-undefined-behavior
	CFLAGS += $(call cc-disable-warning,documentation-unknown-command)
endif

# Add GCC-specific options unknown to clang
ifeq ($(call ccpp-has-option,-Wtrampolines), y)
	CFLAGS += \
		-Wjump-misses-init \
		-Wlogical-op \
		-Wtrampolines
	# gcc 4.6 added -Wsuggest-attribute=[const|pure|noreturn]
	CFLAGS += $(call ccpp-option,-Wsuggest-attribute=format)
	CFLAGS += $(call ccpp-option,-Wsuggest-attribute=noreturn)
	# gcc 4.8 added -fstack-check=specific
	CFLAGS += $(call ccpp-option,-fstack-check=specific)
endif

# Application build configuration
BIN_EXT := $(EXT_PREFIX)bin

# Shared Object build configuration
LIB_EXT := $(EXT_PREFIX)so
LIB_CFLAGS = -fPIC -fvisibility=hidden
LIB_LDFLAGS = -fPIC -shared -Wl,-soname,$@
