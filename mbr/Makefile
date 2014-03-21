all: all..syslinux-mbr

clean: clean..syslinux-mbr

%..syslinux-mbr:
	$(MAKE) -C syslinux-mbr $(firstword $(subst .., ,$@))

.PHONY: all clean %..syslinux-mbr
