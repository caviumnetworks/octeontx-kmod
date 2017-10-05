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

	$ cp ../octeontx-kmod/configs/config_octeontx .config

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
| lbk_main.c          | ONA LBK PF driver				      |
| bgx.c               | ONA BGX PF driver				      |
| pki_main.c          | ONA PKI PF driver				      |
| pkopf_main.c        | ONA PKO PF driver				      |
| timpf_main.c       | ONA TIMER PF driver				      |


## Configs

Has octeontx kernel config.

## Patches

Has patches for kernel and dpdk.

1. Kernel specific patches are in patches/4.9.x directory.

Refer "Build and Install" to apply patches on linux 4.9 kernel.

Cavium PCI device snapshot:

	$ ./usertools/dpdk-devbind.py --status

	Network devices using DPDK-compatible driver
	============================================
	0001:02:00.1 'Device a0dd' drv=vfio-pci unused=
	0001:03:00.1 'Device a049' drv=vfio-pci unused=

	Network devices using kernel driver
	===================================
	0000:01:10.0 'Device a026' if= drv=thunder-BGX unused=vfio-pci
	0000:01:10.1 'Device a026' if= drv=thunder-BGX unused=vfio-pci
	0001:01:00.0 'Device a01e' if= drv=thunder-nic unused=vfio-pci
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

	Other Network devices
	=====================
	0001:01:00.1 'Device a034' unused=vfio-pci
	0001:01:00.2 'Device a034' unused=vfio-pci
	0001:02:00.2 'Device a0dd' unused=vfio-pci
	0001:02:00.3 'Device a0dd' unused=vfio-pci
	0001:02:00.4 'Device a0dd' unused=vfio-pci
	0001:02:00.5 'Device a0dd' unused=vfio-pci
	0001:02:00.6 'Device a0dd' unused=vfio-pci
	0001:02:00.7 'Device a0dd' unused=vfio-pci
	0001:02:01.0 'Device a0dd' unused=vfio-pci
	0001:03:00.2 'Device a049' unused=vfio-pci
	0001:03:00.3 'Device a049' unused=vfio-pci
	0001:03:00.4 'Device a049' unused=vfio-pci
	0001:03:00.5 'Device a049' unused=vfio-pci
	0001:03:00.6 'Device a049' unused=vfio-pci
	0001:03:00.7 'Device a049' unused=vfio-pci
	0001:03:01.0 'Device a049' unused=vfio-pci

	Crypto devices using DPDK-compatible driver
	===========================================

	<none>

	Crypto devices using kernel driver
	==================================
	<none>

	Other Crypto devices
	====================
	0000:04:00.0 'Device a040' unused=vfio-pci
	0000:05:00.0 'Device a040' unused=vfio-pci

	Eventdev devices using DPDK-compatible driver
	=============================================
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
	0000:08:00.7 'Device a04d' drv=vfio-pci unused=
	0000:08:01.0 'Device a04d' drv=vfio-pci unused=

	Eventdev devices using kernel driver
	====================================
	<none>

	Other Eventdev devices
	======================
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

	Mempool devices using DPDK-compatible driver
	============================================
	0000:09:00.3 'Device a053' drv=vfio-pci unused=

	Mempool devices using kernel driver
	===================================
	0000:09:00.1 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:00.2 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:00.4 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:00.5 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:00.6 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:00.7 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.0 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.1 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.2 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.3 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.4 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.5 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.6 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:01.7 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci
	0000:09:02.0 'Device a053' if= drv=octeontx-fpavf unused=vfio-pci

	Other Mempool devices
	=====================
	<none>

Binding Cavium PCI devices to DPDK:

1. Binding 6 queues and 6 ports:

Note that queues are SSOGRP_vf and ports SSOW_VF. SSOGRP_vf
BDF starts from 0000:07:00.1 and SSOW_vf starts from 0000:08:00.1.

So in ordert to bind 6 queues(aka SSOGRP_vf) and 6 ports (aka SSOW_vf),
Use below command:

	$ ./usertools/dpdk-devbind.py -b vfio-pci 0000:08:00.1 0000:08:00.2
		0000:08:00.3 0000:08:00.4 0000:08:00.5 0000:08:00.6
		0000:07:00.1 0000:07:00.2 0000:07:00.3 0000:07:00.4
		0000:07:00.5 0000:07:00.6

2. For single port pktio setup, bind following resources:

Note that the following resource are bind to userspace in below order

	* fpa_vf (bdf start at 0000:09:00.3)
	* ssow_vf (bdf start at 0000:08:00.1)
	* ssogrp_vf (bdf start at 0000:07:00.1)
	* pko_vf (bdf start at 0001:03:00.1)
	* pki_vf (bdf start at 0001:02:00.1)

Use below command:

	$ ./usertools/dpdk-devbind.py -b vfio-pci 0000:09:00.3 0000:08:00.1
		0000:08:00.2 0000:08:00.3 0000:08:00.4  0000:08:00.5
		0000:08:00.6  0000:08:00.7 0000:08:01.0  0000:07:00.1
		0000:07:00.2 0000:07:00.3 0000:07:00.4 0000:07:00.5
		0000:07:00.6  0000:07:00.7  0000:07:01.0 0001:03:00.1
		0001:02:00.1

## dpdk sample network applications commands

sudo ./build/app/testpmd -c 700 --base-virtaddr=0x100000000000 --mbuf-pool-ops="octeontx_fpavf" --vdev='event_octeontx' --vdev='eth_octeontx,nr_port=1' -- --rxq=1 --txq=1 --nb-cores=1 --total-num-mbufs=16384 --port-topology=chained --disable-hw-vlan-filter

sudo ./build/app/testpmd -c 700 --base-virtaddr=0x100000000000 --mbuf-pool-ops="octeontx_fpavf" --vdev='event_octeontx' --vdev='eth_octeontx,nr_port=2' -- --rxq=1 --txq=1 --nb-cores=2 --total-num-mbufs=16384 --disable-hw-vlan-filter

l2fwd command:
sudo ./examples/l2fwd/build/app/l2fwd -l 8-11 --base-virtaddr=0x100000000000 --mbuf-pool-ops="octeontx_fpavf" --vdev='event_octeontx' --vdev='eth_octeontx,nr_port=1' -- -p 0x1 -q 1
sudo ./examples/l2fwd/build/app/l2fwd -l 8-11 --base-virtaddr=0x100000000000 --mbuf-pool-ops="octeontx_fpavf" --vdev='event_octeontx' --vdev='eth_octeontx,nr_port=2' -- -p 0x3 -q 1

l3fwd command:
sudo ./examples/l3fwd/build/l3fwd -c F00 --base-virtaddr=0x100000000000  --vdev='event_octeontx' --vdev='eth_octeontx,nr_port=1' --mbuf-pool-ops="octeontx_fpavf" -- -p 0x1 --config="(0,0,8)" -P

sudo ./examples/l3fwd/build/l3fwd -c F00 --base-virtaddr=0x100000000000  --vdev='event_octeontx' --vdev='eth_octeontx,nr_port=2' --mbuf-pool-ops="octeontx_fpavf" -- -p 0x3 --config="(0,0,8),(1,0,9)" -P

