#!/bin/sh

DOMAIN="mydom;fpa:3;sso:16;ssow:24"
CFGDOMAIN=`echo ${DOMAIN} > /sys/class/octeontx-rm/octtx-ctr/octtx_attr/create_domain`
LISTDOMAIN=`ls /sys/class/octeontx-rm/octtx-ctr/mydom`
SSOVF_CNT=32
SSOWVF_CNT=24
KSRC=src

echo "=========== Install ONA driver ============="
insmod ${KSRC}/fpapf.ko
insmod ${KSRC}/fpavf.ko
insmod ${KSRC}/rst.ko
insmod ${KSRC}/ssopf.ko
insmod ${KSRC}/ssowpf.ko
insmod ${KSRC}/octeontx.ko
echo " ==== Install ONA done ======"

## Enable SRIOV
echo " ==== Enabling SRIOV for ${SSOVF_CNT} ssovf and ${SSOWVF_CNT} ssowvf ======="
echo ${SSOVF_CNT} > /sys/bus/pci/drivers/octeontx-sso/0000\:07\:00.0/sriov_numvfs
echo ${SSOWVF_CNT} > /sys/bus/pci/drivers/octeontx-ssow/0000\:08\:00.0/sriov_numvfs

echo " ==== SRIOV enable done ======"

## Create domain
echo " ==== Creating domain ${DOMAIN} ================"

${CFGDOMAIN}
echo ${LISTDOMAIN}

echo "======= PF Configuration done! ==========="
