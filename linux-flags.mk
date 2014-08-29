# Define some compilation flags for Linux

# Centralize the choice of C compiler here (gcc, clang...)
CC ?= cc

# C preprocessor flags
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2

# C compiler flags
# list of warnings from https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
CFLAGS ?= -O2 -ansi -pedantic -pipe \
	-Wall -W -Wextra \
	-Wfloat-equal \
	-Wformat=2 \
	-Winit-self \
	-Wmissing-declarations \
	-Wmissing-prototypes \
	-Wpointer-arith \
	-Wshadow \
	-Wstrict-prototypes \
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
CFLAGS += -Wtrampolines
endif

# Add string stack protector if supported
ifeq ($(shell $(CC) -fstack-protector-strong -Werror -E - < /dev/null > /dev/null 2>&1 && echo y), y)
CFLAGS += -fstack-protector-strong
endif

# Linker flags
LDFLAGS ?= -Wl,-as-needed,-no-undefined,-z,relro,-z,now \
	-fPIE -pie -fstack-protector

LIBS ?=
