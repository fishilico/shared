# Linux kernel revision with 3 digits
LINUX_VERSION = 3.17.5

# Tools
FRAMAC ?= frama-c
GPG ?= gpg
PATCH ?= patch
QUILT ?= quilt
LN ?= ln
RM ?= rm
SH ?= sh
TOUCH ?= touch
WGET ?= wget
XZ ?= xz

# Linux archives and URLs
LINUX_URL_PUB := https://www.kernel.org/pub/linux/kernel/v3.x/
LINUX_FILE_ARCHIVE := linux-$(basename $(LINUX_VERSION)).tar.xz
LINUX_SIG_ARCHIVE := $(LINUX_FILE_ARCHIVE:%.xz=%.sign)
ifneq ($(suffix $(LINUX_VERSION)), .0)
LINUX_FILE_PATCH := patch-$(LINUX_VERSION).xz
else
LINUX_FILE_PATCH :=
endif
LINUX_SIG_PATCH := $(LINUX_FILE_PATCH:%.xz=%.sign)

# Working directories
SRC_DIR := $(CURDIR)/src-linux-$(LINUX_VERSION)
OUT_BASEDIR := $(CURDIR)/out-linux

# If out-linux is a symlink, use its destination
OUT_BASEDIR_LINK := $(shell readlink $(OUT_BASEDIR) 2>/dev/null)
ifneq ($(OUT_BASEDIR_LINK),)
OUT_BASEDIR := $(OUT_BASEDIR_LINK)
endif

OUT_DIR := $(OUT_BASEDIR)/$(LINUX_VERSION)

# Path to quiltrc
QUILTRC := $(CURDIR)/quiltrc

# Frama-C include directory
FRAMAC_INCDIR := /usr/share/frama-c/libc

# Frama-C generated files in SRCDIR
FRAMAC_GEN_SRC_FILES := $(addprefix $(SRC_DIR)/, \
                          for-frama-c.c for-frama-c.h \
                          include/frama-c-lib.linked include/strings.h)

# Compile User Mode Linux with "-C -save-temps=obj" to save preprocessed files in .i files, with comments.
define compile_kernel
$(MAKE) -C $(OUT_DIR) ARCH=um SUBARCH=x86 \
	KCPPFLAGS='-C -save-temps=obj -D__CHECKER__ -D__FRAMAC__' \
	KCFLAGS='-Wno-attributes -Wno-unused-function -include $(SRC_DIR)/for-frama-c.h' \
	'for-frama-c.o' all
endef

all: $(OUT_DIR)/vmlinux

clean:
	if [ -e $(OUT_DIR)/Makefile ] ; then $(MAKE) -C '$(OUT_DIR)' ARCH=um mrproper ; fi
	$(RM) -rf '$(OUT_DIR)'

mrproper: clean
	$(RM) -r '$(SRC_DIR)'
	$(RM) ./*.sav ./*.sign ./*.xz

# Download files
$(LINUX_FILE_ARCHIVE) $(LINUX_SIG_ARCHIVE) $(LINUX_FILE_PATCH) $(LINUX_SIG_PATCH):
	$(WGET) -O $@ "$(LINUX_URL_PUB)$@" || ($(RM) -f "$@" ; false)

# Extract Linux
$(SRC_DIR)/Makefile: $(LINUX_FILE_ARCHIVE) $(LINUX_SIG_ARCHIVE) $(LINUX_FILE_PATCH) $(LINUX_SIG_PATCH)
	$(XZ) -c -d '$(LINUX_FILE_ARCHIVE)' | $(GPG) --quiet --verify '$(LINUX_SIG_ARCHIVE)' -
	$(RM) -rf '$(SRC_DIR)' 'linux-$(basename $(LINUX_VERSION))'
	tar -xf '$(LINUX_FILE_ARCHIVE)'
	mv 'linux-$(basename $(LINUX_VERSION))' '$(SRC_DIR)'
ifneq ($(LINUX_FILE_PATCH),)
	$(XZ) -c -d '$(LINUX_FILE_PATCH)' | $(GPG) --quiet --verify '$(LINUX_SIG_PATCH)' -
	$(XZ) -c -d '$(LINUX_FILE_PATCH)' | (cd '$(SRC_DIR)' && $(PATCH) -p1)
endif
	$(TOUCH) '$@'

# Copy Frama-C-specific files to source directory
$(SRC_DIR)/for-frama-c.c: $(SRC_DIR)/Makefile
	$(LN) -sf '$(CURDIR)/$(@F)' '$@'
$(SRC_DIR)/for-frama-c.h: $(SRC_DIR)/Makefile
	$(LN) -sf '$(CURDIR)/$(@F)' '$@'
$(SRC_DIR)/include/frama-c-lib.linked: $(SRC_DIR)/Makefile $(FRAMAC_INCDIR)
	$(RM) -f '$(SRC_DIR)/include/frama-c-lib'
	$(LN) -sf '$(FRAMAC_INCDIR)' '$(SRC_DIR)/include/frama-c-lib'
	$(TOUCH) '$@'
# Frama-C needs an empty strings.h file
$(SRC_DIR)/include/strings.h: $(SRC_DIR)/Makefile
	echo '/* Fix Frama-C abusive include in its string.h */' > '$@'

# Apply quilt patches and don't fail if all patches are applied
$(SRC_DIR)/.pc/quilt-called: $(SRC_DIR)/Makefile
	cd '$(SRC_DIR)' && export QUILTRC='$(QUILTRC)' && ($(QUILT) push -a || ! $(QUILT) unapplied)
	$(TOUCH) '$@'

# Refresh all quilt patches, after they have been applied once
# (and don't fail if no patch is applied)
refresh-quilt: $(SRC_DIR)/.pc/quilt-called
	$(RM) '$(SRC_DIR)/.pc/quilt-called'
	cd '$(SRC_DIR)' && export QUILTRC='$(QUILTRC)' && ($(QUILT) pop -a || ! $(QUILT) applied)
	cd '$(SRC_DIR)' && export QUILTRC='$(QUILTRC)' && ( \
		for i in $$($(QUILT) series | wc -l | xargs seq) ; \
		do \
			($(QUILT) push && $(QUILT) refresh -p ab --no-timestamps --no-index) || exit 1 ; \
		done)

# Configure the output directory, creating a temporary directory if it is a
# broken symlink (e.g. to a temporary folder which got deleted)
$(OUT_DIR)/.config: $(SRC_DIR)/Makefile $(SRC_DIR)/.pc/quilt-called
	$(MAKE) -C $(SRC_DIR) O=$(OUT_DIR) ARCH=um allnoconfig

$(OUT_DIR)/vmlinux: $(OUT_DIR)/.config $(FRAMAC_GEN_SRC_FILES)
	$(compile_kernel)

compile: $(OUT_DIR)/.config $(FRAMAC_GEN_SRC_FILES)
	$(compile_kernel)

# Compile and do something else
comp-%:
	$(compile_kernel)
	$(MAKE) $*

# Launch Frama-C value plugin
frama-val: $(OUT_DIR)/vmlinux
	$(FRAMAC) -save frama-linux-$(LINUX_VERSION).sav \
		-cpp-command 'cat %1 > %2' \
		-main linux_main \
		-val -context-depth=2 -val-show-progress \
		$$(find $(OUT_DIR) \( -path 'arch/um/kernel/asm-offsets.i' -o -path 'kernel/bounds.i' -o -path 'scripts' \) -prune -o -name '*.i' -print |sort) \
		2>&1 | $(SH) ./filter_framac_output.sh

.PHONY: all clean comp-% compile frama-val mrproper refresh-quilt
