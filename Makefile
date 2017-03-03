KDIR ?= /lib/modules/`uname -r`/build

COMMON_ARGS := -C $(KDIR) M=`pwd`/src

build:
	$(MAKE)  $(COMMON_ARGS) modules

clean:
	$(MAKE) -C $(KDIR) M=`pwd` clean

.PHONY: build clean
