#!/bin/sh

DOMAIN="mydomain;ssow:24;sso:32;fpa:4;pko:1;pki:1;tim:1;net:0"
CFGDOMAIN=`echo ${DOMAIN} > /sys/class/octeontx-rm/octtx-ctr/octtx_attr/create_domain`
LISTDOMAIN=`ls /sys/class/octeontx-rm/octtx-ctr/mydomain`
SSOVF_CNT=32
SSOWVF_CNT=24
PKIVF_CNT=8
PKOVF_CNT=8
TIMVF_CNT=8
KSRC=src

echo "=========== Install ONA driver ============="
insmod ${KSRC}/fpapf.ko
insmod ${KSRC}/fpavf.ko
insmod ${KSRC}/rst.ko
insmod ${KSRC}/ssopf.ko
insmod ${KSRC}/ssowpf.ko
insmod ${KSRC}/pkopf.ko
insmod ${KSRC}/lbk.ko
insmod ${KSRC}/timpf.ko
insmod ${KSRC}/pki.ko
insmod ${KSRC}/octeontx.ko
echo " ==== Install ONA done ======"

## Enable SRIOV
echo " ==== Enabling SRIOV for ${SSOVF_CNT} ssovf and ${SSOWVF_CNT} ssowvf ======="
echo ${SSOVF_CNT} > /sys/bus/pci/drivers/octeontx-sso/0000\:07\:00.0/sriov_numvfs
echo ${SSOWVF_CNT} > /sys/bus/pci/drivers/octeontx-ssow/0000\:08\:00.0/sriov_numvfs

echo " ==== Enabling SRIOV for ${PKIVF_CNT} pkivf and ${PKOVF_CNT} pkovf ======="
echo ${PKIVF_CNT} > /sys/bus/pci/drivers/octeontx-pki/0001\:02\:00.0/sriov_numvfs
echo ${PKOVF_CNT} > /sys/bus/pci/drivers/octeontx-pko/0001\:03\:00.0/sriov_numvfs

echo " ==== Enabling SRIOV for ${TIMVF_CNT} timvf  ======="
echo ${TIMVF_CNT} > /sys/bus/pci/drivers/octeontx-tim/0000\:0a\:00.0/sriov_numvfs

echo " ==== SRIOV enable done ======"

## Create domain
echo " ==== Creating domain ${DOMAIN} ================"

${CFGDOMAIN}
echo ${LISTDOMAIN}

echo "======= PF Configuration done! ==========="
