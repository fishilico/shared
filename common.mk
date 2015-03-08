# Makefile definitions which are common to every projects

# Define "quiet" commands, with V=1, like git and systemd project
ifneq ($(findstring $(MAKEFLAGS), s), s)
ifndef V
V_CC        = @echo '  CC        $<';
V_CCAS      = @echo '  CCAS      $<';
V_CCLD      = @echo '  CCLD      $@';
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
	*.a *.aux *.bin *.dll *.efi *.elf *.exe *.log *.o *.out *.pdf *.so *.tmp \
	*.toc .*.d .*.o && \
	$(RM) -r __pycache__
