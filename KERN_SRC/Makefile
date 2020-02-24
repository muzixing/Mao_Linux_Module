
obj-m		:= MaoNetHook.o
ccflags-m	:= -O2

PWD			:= $(shell pwd)
KERN_SRC	:= /lib/modules/$(shell uname -r)/build/

modules:
	make -C $(KERN_SRC) M=$(PWD) modules

install:
	make -C $(KERN_SRC) M=$(PWD) modules_install
	depmod -a

clean:
	make -C $(KERN_SRC) M=$(PWD) clean
