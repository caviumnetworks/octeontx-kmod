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

	Note that `install.sh` will insert the module and configure
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

## Configs

Has octeontx kernel config.

## Patches

Has patches for kernel and dpdk.

1. Kernel specific patches are in 4.9.x directory.

Refer "Build and Install" to apply patches on linux 4.9 kernel.

2. DPDK specific patches are in dpdk directory.

Apply patch on top of dpdk:

	$ git am dpdk/*.patch

It's a temporary hack to let dpdk's binding script detect Cavm PCI devices.

	$ ./usertools/dpdk-devbind.py --status

	Network devices using DPDK-compatible driver
	============================================
	<none>

	Network devices using kernel driver
	===================================
	0000:01:10.0 'Device a026' if= drv=thunder-BGX unused=vfio-pci 
	0000:01:10.1 'Device a026' if= drv=thunder-BGX unused=vfio-pci 
	0001:01:00.0 'Device a01e' if= drv=thunder-nic unused=vfio-pci 
	0001:01:00.1 'Device a034' if=eth6 drv=thunder-nicvf unused=vfio-pci 
	0001:01:00.2 'Device a034' if=eth5 drv=thunder-nicvf unused=vfio-pci 
	0001:01:00.3 'Device a034' if= drv=thunder-nicvf unused=vfio-pci 
	0001:01:00.4 'Device a034' if= drv=thunder-nicvf unused=vfio-pci 
	0001:01:00.5 'Device a034' if= drv=thunder-nicvf unused=vfio-pci 
	0001:01:00.6 'Device a034' if= drv=thunder-nicvf unused=vfio-pci 
	0001:01:00.7 'Device a034' if= drv=thunder-nicvf unused=vfio-pci 
	0001:01:01.0 'Device a034' if= drv=thunder-nicvf unused=vfio-pci 
	0001:01:01.1 'Device a034' if= drv=thunder-nicvf unused=vfio-pci 
	0001:01:01.2 'Device a034' if= drv=thunder-nicvf unused=vfio-pci 
	0001:01:01.3 'Device a034' if= drv=thunder-nicvf unused=vfio-pci 
	0001:01:01.4 'Device a034' if= drv=thunder-nicvf unused=vfio-pci 

	Other network devices
	=====================
	<none>

	Crypto devices using DPDK-compatible driver
	===========================================
	0000:07:00.1 'Device a04b' drv=vfio-pci unused=
	0000:07:00.2 'Device a04b' drv=vfio-pci unused=
	0000:07:00.3 'Device a04b' drv=vfio-pci unused=
	0000:07:00.4 'Device a04b' drv=vfio-pci unused=
	0000:07:00.5 'Device a04b' drv=vfio-pci unused=
	0000:07:00.6 'Device a04b' drv=vfio-pci unused=
	0000:07:00.7 'Device a04b' drv=vfio-pci unused=
	0000:07:01.0 'Device a04b' drv=vfio-pci unused=
	0000:08:00.1 'Device a04d' drv=vfio-pci unused=
	0000:08:00.2 'Device a04d' drv=vfio-pci unused=
	0000:08:00.3 'Device a04d' drv=vfio-pci unused=
	0000:08:00.4 'Device a04d' drv=vfio-pci unused=
	0000:08:00.5 'Device a04d' drv=vfio-pci unused=
	0000:08:00.6 'Device a04d' drv=vfio-pci unused=

	Crypto devices using kernel driver
	==================================
	0000:01:00.1 'Device a00e' drv=octeontx-rst unused=vfio-pci
	0000:07:00.0 'Device a04a' drv=octeontx-sso unused=vfio-pci
	0000:08:00.0 'Device a04c' drv=octeontx-ssow unused=vfio-pci
	0000:09:00.0 'Device a052' drv=octeontx-fpa unused=vfio-pci
	0000:09:00.1 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:00.2 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:00.3 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:00.4 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:00.5 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:00.6 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:00.7 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.0 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.1 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.2 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.3 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.4 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.5 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.6 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.7 'Device a053' drv=octeontx-fpavf unused=vfio-pci
	0000:09:02.0 'Device a053' drv=octeontx-fpavf unused=vfio-pci

	Other crypto devices
	====================
	0000:01:00.0 'Device a001' unused=vfio-pci
	0000:01:01.7 'Device a035' unused=vfio-pci
	0000:01:0c.0 'Device a023' unused=vfio-pci
	0000:01:0c.1 'Device a023' unused=vfio-pci
	0000:01:0c.2 'Device a023' unused=vfio-pci
	0000:01:0d.0 'Device a042' unused=vfio-pci
	0000:01:0d.1 'Device a042' unused=vfio-pci
	0000:01:0d.2 'Device a042' unused=vfio-pci
	0000:01:0d.3 'Device a042' unused=vfio-pci
	0000:07:01.1 'Device a04b' unused=vfio-pci
	0000:07:01.2 'Device a04b' unused=vfio-pci
	0000:07:01.3 'Device a04b' unused=vfio-pci
	0000:07:01.4 'Device a04b' unused=vfio-pci
	0000:07:01.5 'Device a04b' unused=vfio-pci
	0000:07:01.6 'Device a04b' unused=vfio-pci
	0000:07:01.7 'Device a04b' unused=vfio-pci
	0000:07:02.0 'Device a04b' unused=vfio-pci
	0000:07:02.1 'Device a04b' unused=vfio-pci
	0000:07:02.2 'Device a04b' unused=vfio-pci
	0000:07:02.3 'Device a04b' unused=vfio-pci
	0000:07:02.4 'Device a04b' unused=vfio-pci
	0000:07:02.5 'Device a04b' unused=vfio-pci
	0000:07:02.6 'Device a04b' unused=vfio-pci
	0000:07:02.7 'Device a04b' unused=vfio-pci
	0000:07:03.0 'Device a04b' unused=vfio-pci
	0000:07:03.1 'Device a04b' unused=vfio-pci
	0000:07:03.2 'Device a04b' unused=vfio-pci
	0000:07:03.3 'Device a04b' unused=vfio-pci
	0000:07:03.4 'Device a04b' unused=vfio-pci
	0000:07:03.5 'Device a04b' unused=vfio-pci
	0000:07:03.6 'Device a04b' unused=vfio-pci
	0000:07:03.7 'Device a04b' unused=vfio-pci
	0000:07:04.0 'Device a04b' unused=vfio-pci
	0000:08:00.7 'Device a04d' unused=vfio-pci
	0000:08:01.0 'Device a04d' unused=vfio-pci
	0000:08:01.1 'Device a04d' unused=vfio-pci
	0000:08:01.2 'Device a04d' unused=vfio-pci
	0000:08:01.3 'Device a04d' unused=vfio-pci
	0000:08:01.4 'Device a04d' unused=vfio-pci
	0000:08:01.5 'Device a04d' unused=vfio-pci
	0000:08:01.6 'Device a04d' unused=vfio-pci
	0000:08:01.7 'Device a04d' unused=vfio-pci
	0000:08:02.0 'Device a04d' unused=vfio-pci
	0000:08:02.1 'Device a04d' unused=vfio-pci
	0000:08:02.2 'Device a04d' unused=vfio-pci
	0000:08:02.3 'Device a04d' unused=vfio-pci
	0000:08:02.4 'Device a04d' unused=vfio-pci
	0000:08:02.5 'Device a04d' unused=vfio-pci
	0000:08:02.6 'Device a04d' unused=vfio-pci
	0000:08:02.7 'Device a04d' unused=vfio-pci
	0000:08:03.0 'Device a04d' unused=vfio-pci
	0000:0a:00.0 'Device a050' unused=vfio-pci
	0000:0b:00.0 'Device a057' unused=vfio-pci
	0001:02:00.0 'Device a047' unused=vfio-pci
	0001:03:00.0 'Device a048' unused=vfio-pci
	0001:05:00.0 'Device a045' unused=vfio-pci

