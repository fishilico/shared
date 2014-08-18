obj-m += cpu_x86.o
obj-m += hello_world.o
obj-m += proc_setroot.o

# Uncomment to retrieve the prepropressor output
#ccflags-y += -save-temps=obj

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

# Some targets added to list useful commands
infos:
	modinfo *.ko

.PHONY: all clean infos
