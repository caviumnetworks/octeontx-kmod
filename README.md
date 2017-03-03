# OcteonTX Network Accelerator Resource Manager Kernel Drivers

These drivers support Cavium's T83 family of Network processor device.

This archive builds bunch of module, Out of which octeontx.ko module creates
domain. A domain is collection of accelerator blocks. Octeontx.ko exposes
sysfs so to reconfigure domain.

For more information Or If questions arise or an issue is identified related
the released driver code, please email us on:

octeontx-kmod@caviumnetworks.microsoftonline.com

# Building and Installing

Clone Octeontx-kmod repo:

	$ git clone https://github.com/caviumnetworks/octeontx-kmod

Clone linux.git repo:

	$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
	$ git checkout -b linux-v4.9 v4.9

Apply octeontx-kmod specific patches to kernel:

	$ cd linux
	$ git am ../octeontx-kmod/patches/4.9.x/*.patch

Copy octeontx config to linux :

	$ cp ../octeontx-kmo/configs/config_octeontx .

Build and Install the kernel on Octeontx(T83) target:

	$ make menuconfig
	$ make -j32
	$ make modules_install -j12.

Reboot to latest installed kernel.

Build octeontx-kmod drv:

	$ cd ../octeontx-kmod
	$ make clean
	$ make build

Install and configure octeontx driver:

	$ ./install.sh

	Note that `Install.sh` will insert the module and configures
	the resource manager.

## RM driver

ONA driver is a Resource Manager aka Collecton of PF drivers. Its job is to
configure resources for VF's and establish a communication link between
PF <--> VF.

## Sources

| Source              | Description                                           |
| ------------------- | ----------------------------------------------------- |
| octeontx_main.c     | ONA Resource manager				      |
| octeontx_mbox.c     | ONA mailbox used for pf <--> vf communication         |
| rst_main.c	      | ONA reset driver                                      |
| fpapf_main.c        | ONA External mempool PF driver                        |
| ssopf_main.c        | ONA Event based Schedular PF driver                   |
| ssowpf_main.c       | ONA HWS PF driver				      |

