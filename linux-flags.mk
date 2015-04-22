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
# Generate dependencies files targetting $@ in a .$@.d file
# ... while allowing using CPPFLAGS outside of a target (where $@ is empty)
CPPFLAGS ?= -D_FORTIFY_SOURCE=2 $(@:%=-Wp,-MT,$@ -Wp,-MD,$(dir $@).$(notdir $@).d)

# C compiler flags
# list of warnings from https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
CFLAGS ?= -O2 -ansi -pedantic -pipe \
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
	-fPIE  \
	-fno-exceptions \
	-fstack-protector --param=ssp-buffer-size=4 \
	-fvisibility=hidden

# Uncomment the next line to enable debug
#CFLAGS += -g -fvar-tracking-assignments -fno-omit-frame-pointer

# Add clang-specific options unknown to GCC
ifeq ($(shell $(CC) -Werror -Weverything -E - < /dev/null > /dev/null 2>&1 && echo y), y)
	CFLAGS += -Weverything \
		-Wno-disabled-macro-expansion \
		-Wno-documentation \
		-Wno-padded \
		-Wno-shift-sign-overflow \
		-Wno-unused-macros
	# clang 3.6 added -Wreserved-id-macro, which is incompatible with _GNU_SOURCE definition
	ifeq ($(shell $(CC) -Werror -Wreserved-id-macro -E - < /dev/null > /dev/null 2>&1 && echo y), y)
		CFLAGS += -Wno-reserved-id-macro
	endif
endif

# Add GCC-specific options unknown to clang
ifeq ($(shell $(CC) -Werror -Wtrampolines -E - < /dev/null > /dev/null 2>&1 && echo y), y)
	CFLAGS += \
		-Wjump-misses-init \
		-Wlogical-op \
		-Wtrampolines
	# gcc 4.6 added -Wsuggest-attribute=[const|pure|noreturn]
	ifeq ($(shell $(CC) -Werror -Wsuggest-attribute=format -E - < /dev/null > /dev/null 2>&1 && echo y), y)
		CFLAGS += \
			-Wsuggest-attribute=format \
			-Wsuggest-attribute=noreturn
	endif
endif

# Add strong stack protector if supported
ifeq ($(shell $(CC) -Werror -fstack-protector-strong -E - < /dev/null > /dev/null 2>&1 && echo y), y)
	CFLAGS += -fstack-protector-strong
endif

# Linker flags
LDFLAGS ?= -Wl,-O1,-as-needed,-no-undefined,-z,relro,-z,now \
	-fPIE -pie -fstack-protector

LIBS ?=

# Application build configuration
BIN_EXT := $(EXT_PREFIX)bin

# Shared Object build configuration
LIB_EXT := $(EXT_PREFIX)so
LIB_CFLAGS ?= -fPIC -fvisibility=hidden
LIB_LDFLAGS ?= -fPIC -shared -Wl,-soname,$@
