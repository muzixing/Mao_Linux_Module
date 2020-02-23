
obj-m		:= MaoNetHook.o 

PWD			:= $(shell pwd)

NOT_TRAVIS_CI := $(shell uname -r | grep gcp)
ifeq ($(NOT_TRAVIS_CI),)
	KERN_SRC	:= /lib/modules/$(shell uname -r)/build/
else
	KERN_SRC	:= /usr/src/linux-gcp-headers-5.0.0-1026/
endif

modules:
	make -C $(KERN_SRC) M=$(PWD) modules

install:
	make -C $(KERN_SRC) M=$(PWD) modules_install
	depmod -a

clean:
	make -C $(KERN_SRC) M=$(PWD) clean
	