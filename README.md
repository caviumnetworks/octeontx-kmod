# octeontx-kmod
OcteonTX network accelerator resource manager kernel module

## Steps to build/install octeontx-kmod drv and configure resource manager.

1) Clone Octeontx-kmod repo.
git clone https://github.com/caviumnetworks/octeontx-kmod

2) Clone linux.git repo.
>> git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
>> git checkout -b linux-v4.9 v4.9

2.0) Apply octeontx-kmod specific patches.
>> cd linux
>> git am ../octeontx-kmod/4.9.x/*.patch

2.1) Then build and install the kernel on Octeontx target.
make -j32 && make modules_install -j12.

2.2) Reboot to latest installed kernel.

3) Install octeontx-kmod drv and configure resource manager.
>> cd octeontx-kmod
>> ./install.sh

Note that `Install.sh` will build/insert the module and configures
the resource manager.

