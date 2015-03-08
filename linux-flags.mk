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

# Centralize the choice of C compiler here (gcc, clang...)
CC ?= cc

# C preprocessor flags
CPPFLAGS ?= -D_FORTIFY_SOURCE=2

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
ifeq ($(shell $(CC) -Weverything -Werror -E - < /dev/null > /dev/null 2>&1 && echo y), y)
CFLAGS += -Weverything \
	-Wno-disabled-macro-expansion \
	-Wno-documentation \
	-Wno-padded \
	-Wno-shift-sign-overflow \
	-Wno-unused-macros
endif

# Add GCC-specific options unknown to clang
ifeq ($(shell $(CC) -Wtrampolines -Werror -E - < /dev/null > /dev/null 2>&1 && echo y), y)
CFLAGS += \
	-Wjump-misses-init \
	-Wlogical-op \
	-Wtrampolines
	# -Wsuggest-attribute=noreturn and -Wsuggest-attribute=format are also available for recent gcc
endif

# Add strong stack protector if supported
ifeq ($(shell $(CC) -fstack-protector-strong -Werror -E - < /dev/null > /dev/null 2>&1 && echo y), y)
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
