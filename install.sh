#!/bin/sh

CFGDOMAIN=`echo "mydom;fpa:3;sso:16;ssow:24" > /sys/class/octeontx-rm/octtx-ctr/octtx_attr/create_domain`
LISTDOMAIN=`ls /sys/class/octeontx-rm/octtx-ctr/mydom`
SSOVF_CNT=32
SSOWVF_CNT=24


echo "=========== Build ONA driver ==================="
#make clean && make
echo "=========== Build done ========"

sleep 2
echo "=========== Install ONA driver ============="
insmod fpapf.ko
insmod fpavf.ko
insmod rst.ko
insmod ssopf.ko
insmod ssowpf.ko
insmod octeontx.ko
echo " ==== Install ONA done ======"

sleep 2
## Enable SRIOV
echo " ==== Enabling SRIOV for $SSOVF_CNT ssovf and $SSOWVF_CNT ssowvf ======="
echo $SSOVF_CNT > /sys/bus/pci/drivers/octeontx-sso/0000\:07\:00.0/sriov_numvfs
echo $SSOWVF_CNT > /sys/bus/pci/drivers/octeontx-ssow/0000\:08\:00.0/sriov_numvfs

echo " ==== SRIOV enable done ======"

## Create domain
echo " ==== Creating domain --> mydom;fpa:3;sso:32;ssow:24 ================"

$CFGDOMAIN
echo $LISTDOMAIN

echo "======= PF Configuration done! ==========="
