obj-m += lkm.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm lkm.o.ur-safe

install:
	sudo insmod lkm.ko

remove:
	sudo rmmod lkm
