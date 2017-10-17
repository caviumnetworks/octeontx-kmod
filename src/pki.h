/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef PKI_H
#define PKI_H

#include <linux/pci.h>
#include <linux/types.h>
#include "octeontx.h"

/* PCI DEV ID */
#define PCI_DEVICE_ID_OCTEONTX_PKI	0xA047

#define PCI_PKI_CFG_BAR			0
#define PCI_PKI_MSIX_BAR		4

#define PKI_MSIX_COUNT			16

/*PKI Register offsets */
#define PKI_CONST			0x0
#define PKI_CONST1			0x8
#define PKI_CONST2			0x10
#define PKI_CONST3			0x18
#define PKI_SFT_RST			0x20
#define PKI_PKT_ERR			0x30
#define PKI_X2P_REQ_OFL			0x38
#define	PKI_ECC0_CTL			0x60
#define	PKI_ECC1_CTL			0x68
#define PKI_ECC2_CTL			0x70
#define PKI_BIST_STATUS0		0x80
#define PKI_BIST_STATUS1		0x88
#define PKI_BIST_STATUS2		0x90
#define PKI_BUF_CTL			0x100
#define PKI_STAT_CTL			0x110
#define PKI_REQ_WGT			0x120
#define PKI_PTAG_AVIAL			0x130
#define PKI_ACTIVE0			0x220
#define PKI_ACTIVE1			0x230
#define PKI_ACTIVE2			0x240
#define PKI_CLKEN			0x410
#define PKI_TAG_SECRET			0x430
#define PKI_PCAM_LOOKUP			0x500
#define PKI_PCAM_RESULT			0x510
#define PKI_GEN_INT			0x800
#define PKI_GEN_INT_W1S			0x810
#define PKI_GEN_INT_ENA_W1C		0x820
#define PKI_GEN_INT_ENA_W1S		0x830
#define PKI_ECC0_INT			0x840
#define PKI_ECC0_INT_W1S		0x850
#define PKI_ECC0_INT_ENA_W1C		0x860
#define PKI_ECC0_INT_ENA_W1S		0x870
#define PKI_ECC1_INT			0x880
#define PKI_ECC1_INT_W1S		0x890
#define PKI_ECC1_INT_ENA_W1C		0x8A0
#define PKI_ECC1_INT_ENA_W1S		0x8B0
#define PKI_ECC2_INT			0x8C0
#define PKI_ECC2_INT_W1S		0x8D0
#define PKI_ECC2_INT_ENA_W1C		0x8E0
#define PKI_ECC2_INT_ENA_W1S		0x8F0
#define PKI_ALLOC_FLTX_INT(x)		(0x900 | ((x) << 3))
#define PKI_ALLOC_FLTX_INT_W1S(x)	(0x920 | ((x) << 3))
#define PKI_ALLOC_FLTX_INT_ENA_W1C(x)	(0x940 | ((x) << 3))
#define PKI_ALLOC_FLTX_INT_ENA_W1S(x)	(0x960 | ((x) << 3))
#define PKI_STRM_FLTX_INT(x)		(0x980 | ((x) << 3))
#define PKI_STRM_FLTX_INT_W1S(x)	(0x9A0 | ((x) << 3))
#define PKI_STRM_FLTX_INT_ENA_W1C(x)	(0x9C0 | ((x) << 3))
#define PKI_STRM_FLTX_INT_ENA_W1S(x)	(0x9E0 | ((x) << 3))
#define PKI_ALLOC_FLT_DEBUG		0xA00
#define PKI_FRM_LEN_CHKX(x)		(0x4000 | ((x) << 3))
#define PKI_LTYPEX_MAP(x)		(0x5000 | ((x) << 3))
#define PKI_REASM_SOPX(x)		(0x6000 | ((x) << 3))
#define PKI_TAG_INCX_CTL(x)		(0x7000 | ((x) << 3))
#define PKI_TAG_INCX_MASK(x)		(0x8000 | ((x) << 3))
#define PKI_ICGX_CFG(x)			(0xA000 | ((x) << 3))
#define PKI_CLX_ECC_CTL(x)		(0xC020 | ((x) << 16))
#define PKI_CLX_START(x)		(0xC030 | ((x) << 16))
#define PKI_CLX_INT(x)			(0xC100 | ((x) << 16))
#define PKI_CLX_INT_W1S(x)		(0xC110 | ((x) << 16))
#define PKI_CLX_INT_ENA_W1C(x)		(0xC120 | ((x) << 16))
#define PKI_CLX_INT_ENA_W1S(x)		(0xC130 | ((x) << 16))
#define PKI_CLX_ECC_INT(x)		(0xC200 | ((x) << 16))
#define PKI_CLX_ECC_INT_W1S(x)		(0xC210 | ((x) << 16))
#define PKI_CLX_ECC_INT_ENA_W1C(x)	(0xC220 | ((x) << 16))
#define PKI_CLX_ECC_INT_ENA_W1S(x)	(0xC230 | ((x) << 16))
#define PKI_PKINDX_ICGSEL(x)		(0x10000 | ((x) << 3))
#define PKI_STYLEX_TAG_SEL(x)		(0x20000 | ((x) << 3))
#define PKI_STYLEX_TAG_MASK(x)		(0x21000 | ((x) << 3))
#define PKI_STYLEX_WQ2(x)		(0x22000 | ((x) << 3))
#define PKI_STYLEX_WQ4(x)		(0x23000 | ((x) << 3))
#define PKI_STYLEX_BUF(x)		(0x24000 | ((x) << 3))
#define PKI_IMEM(x)			(0x100000 | ((x) << 3))
#define PKI_CLX_PKINDX_KMEMX(x, y, z)	(0x200000 | ((x) << 16) | ((y) << 8) | \
		((z) << 3))
#define PKI_CLX_PKINDX_CFG(x, y)	(0x300040 | ((x) << 16) | ((y) << 8))
#define PKI_CLX_PKINDX_STYLE(x, y)	(0x300048 | ((x) << 16) | ((y) << 8))
#define PKI_CLX_PKINDX_SKIP(x, y)	(0x300050 | ((x) << 16) | ((y) << 8))
#define PKI_CLX_PKINDX_L2_CUSTOM(x, y)	(0x300058 | ((x) << 16) | ((y) << 8))
#define PKI_CLX_PKINDX_LG_CUSTOM(x, y)	(0x300060 | ((x) << 16) | ((y) << 8))
#define PKI_CLX_SMEMX(x, y)		(0x400000 | ((x) << 16) | ((y) << 3))
#define PKI_CLX_STYLEX_CFG(x, y)	(0x500000 | ((x) << 16) | ((y) << 3))
#define PKI_CLX_STYLEX_CFG2(x, y)	(0x500800 | ((x) << 16) | ((y) << 3))
#define PKI_CLX_STYLEX_ALG(x, y)	(0x501000 | ((x) << 16) | ((y) << 3))
#define PKI_CLX_PCAMX_TERMX(x, y, z)	(0x700000 | ((x) << 16) | ((y) << 12) |\
		       ((z) << 3))
#define PKI_CLX_PCAMX_MATCHX(x, y, z)	(0x704000 | ((x) << 16) | ((y) << 12) |\
		       ((z) << 3))
#define PKI_CLX_PCAMX_ACTIONX(x, y, z)	(0x708000 | ((x) << 16) | ((y) << 12) |\
		       ((z) << 3))
#define PKI_QPG_TBLX(x)			(0x800000 | ((x) << 3))
#define PKI_QPG_TBLBX(x)		(0x820000 | ((x) << 3))
#define PKI_STRMX_CFG(x)		(0x840000 | ((x) << 3))
#define PKI_AURAX_CFG(x)		(0x900000 | ((x) << 3))
#define PKI_CHANX_CFG(x)		(0xA00000 | ((x) << 3))
#define PKI_BPIDX_STATE(x)		(0xB00000 | ((x) << 3))
#define PKI_DSTATX_STAT0(x)		(0xC00000 | ((x) << 6))
#define PKI_DSTATX_STAT1(x)		(0xC00008 | ((x) << 6))
#define PKI_DSTATX_STAT2(x)		(0xC00010 | ((x) << 6))
#define PKI_DSTATX_STAT3(x)		(0xC00018 | ((x) << 6))
#define PKI_DSTATX_STAT4(x)		(0xC00020 | ((x) << 6))
#define PKI_STATX_HIST0(x)		(0xE00000 | ((x) << 8))
#define PKI_STATX_HIST1(x)		(0xE00008 | ((x) << 8))
#define PKI_STATX_HIST2(x)		(0xE00010 | ((x) << 8))
#define PKI_STATX_HIST3(x)		(0xE00018 | ((x) << 8))
#define PKI_STATX_HIST4(x)		(0xE00020 | ((x) << 8))
#define PKI_STATX_HIST5(x)		(0xE00028 | ((x) << 8))
#define PKI_STATX_HIST6(x)		(0xE00030 | ((x) << 8))
#define PKI_STATX_STAT0(x)		(0xE00038 | ((x) << 8))
#define PKI_STATX_STAT1(x)		(0xE00040 | ((x) << 8))
#define PKI_STATX_STAT2(x)		(0xE00048 | ((x) << 8))
#define PKI_STATX_STAT3(x)		(0xE00050 | ((x) << 8))
#define PKI_STATX_STAT4(x)		(0xE00058 | ((x) << 8))
#define PKI_STATX_STAT5(x)		(0xE00060 | ((x) << 8))
#define PKI_STATX_STAT6(x)		(0xE00068 | ((x) << 8))
#define PKI_STATX_STAT7(x)		(0xE00070 | ((x) << 8))
#define PKI_STATX_STAT8(x)		(0xE00078 | ((x) << 8))
#define PKI_STATX_STAT9(x)		(0xE00080 | ((x) << 8))
#define PKI_STATX_STAT10(x)		(0xE00088 | ((x) << 8))
#define PKI_STATX_STAT11(x)		(0xE00090 | ((x) << 8))
#define PKI_STATX_STAT12(x)		(0xE00098 | ((x) << 8))
#define PKI_STATX_STAT13(x)		(0xE000A0 | ((x) << 8))
#define PKI_STATX_STAT14(x)		(0xE000A8 | ((x) << 8))
#define PKI_STATX_STAT15(x)		(0xE000B0 | ((x) << 8))
#define PKI_STATX_STAT16(x)		(0xE000B8 | ((x) << 8))
#define PKI_STATX_STAT17(x)		(0xE000C0 | ((x) << 8))
#define PKI_STATX_STAT18(x)		(0xE000C8 | ((x) << 8))
#define PKI_PKINDX_INB_STAT0(x)		(0xF00000 | ((x) << 8))
#define PKI_PKINDX_INB_STAT1(x)		(0xF00008 | ((x) << 8))
#define PKI_PKINDX_INB_STAT2(x)		(0xF00010 | ((x) << 8))
#define PKI_PBE_PCE_FLUSH_DETECT	0xFFF080

#define PKI_CONST_AURAS_MASK		0xffff
#define PKI_CONST_AURAS_SHIFT		0
#define PKI_CONST_BPID_MASK		0xffff
#define PKI_CONST_BPID_SHIFT		16
#define PKI_CONST_PKNDS_MASK		0xffff
#define PKI_CONST_PKNDS_SHIFT		32
#define PKI_CONST_FSTYLES_MASK		0xffff
#define PKI_CONST_FSTYLES_SHIFT		48

#define PKI_CONST1_CLS_MASK		0xff
#define PKI_CONST1_CLS_SHIFT		0
#define PKI_CONST1_IPES_MASK		0xff
#define PKI_CONST1_IPES_SHIFT		8
#define PKI_CONST1_PCAMS_MASK		0xff
#define PKI_CONST1_PCAMS_SHIFT		16

#define PKI_CONST2_PCAM_ENTS_MASK	0xffff
#define PKI_CONST2_PCAM_ENTS_SHIFT	0
#define PKI_CONST2_QPGS_MASK		0xffff
#define PKI_CONST2_QPGS_SHIFT		16
#define PKI_CONST2_DSTATS_MASK		0xffff
#define PKI_CONST2_DSTATS_SHIFT		32
#define PKI_CONST2_STATS_MASK		0xffff
#define PKI_CONST2_STATS_SHIFT		48

#define PKI_PKIND_STYLE_MASK		0xffULL
#define PKI_PKIND_STYLE_SHIFT		0
#define PKI_PKIND_CFG_FCS_SHIFT		7

#define PKI_STYLE_ALG_TT_MASK			0x3
#define PKI_STLYE_ALG_TT_SHIFT			30
#define PKI_STYLE_ALG_QPG_QOS_MASK		0x7
#define PKI_STYLE_ALG_QPG_QOS_SHIFT		24
#define PKI_STYLE_ALG_TAG_VNI_SHIFT		10
#define PKI_STYLE_ALG_TAG_GTP_SHIFT		9
#define PKI_STYLE_ALG_TAG_SPI_SHIFT		8
#define PKI_STYLE_ALG_TAG_SYN_SHIFT		7
#define PKI_STYLE_ALG_TAG_PCTL_SHIFT	6
#define PKI_STYLE_ALG_TAG_VS1_SHIFT		5
#define PKI_STYLE_ALG_TAG_VS0_SHIFT		4
#define PKI_STYLE_ALG_TAG_PRT_SHIFT		1

#define PKI_STYLE_CFG_QPG_BASE_MASK	0x7ffULL
#define PKI_STYLE_CFG_DROP_MASK		0x1
#define PKI_STYLE_CFG_QPG_DIS_PADD_SHIFT	18
#define PKI_STYLE_CFG_DROP_SHIFT	20
#define PKI_STYLE_CFG_FCS_CHK_SHIFT	22
#define PKI_STYLE_CFG_FCS_STRIP_SHIFT	23
#define PKI_STYLE_CFG_QPG_DIS_GRPTAG_SHIFT	24
#define PKI_STYLE_CFG_MINERR_EN_SHIFT	25
#define PKI_STYLE_CFG_MAXERR_EN_SHIFT	26
#define PKI_STYLE_CFG_MINMAX_SEL_SHIFT	27
#define PKI_STYLE_CFG_LENERR_EN_SHIFT	29
#define PKI_STYLE_CFG_IP6UDP_SHIFT		30

#define PKI_STYLE_CFG2_CSUM_LC_SHIFT	1
#define PKI_STYLE_CFG2_CSUM_LD_SHIFT	2
#define PKI_STYLE_CFG2_CSUM_LE_SHIFT	3
#define PKI_STYLE_CFG2_CSUM_LF_SHIFT	4
#define PKI_STYLE_CFG2_LEN_LC_SHIFT		7
#define PKI_STYLE_CFG2_LEN_LD_SHIFT		8
#define PKI_STYLE_CFG2_LEN_LE_SHIFT		9
#define PKI_STYLE_CFG2_LEN_LF_SHIFT		10
#define PKI_STYLE_CFG2_TAG_DLC_SHIFT	13
#define PKI_STYLE_CFG2_TAG_DLD_SHIFT	14
#define PKI_STYLE_CFG2_TAG_DLE_SHIFT	15
#define PKI_STYLE_CFG2_TAG_DLF_SHIFT	16
#define PKI_STYLE_CFG2_TAG_SLC_SHIFT	19
#define PKI_STYLE_CFG2_TAG_SLD_SHIFT	20
#define PKI_STYLE_CFG2_TAG_SLE_SHIFT	21
#define PKI_STYLE_CFG2_TAG_SLF_SHIFT	22

#define PKI_PCAM_TERM_STYLE0_MASK	0xffULL
#define PKI_PCAM_TERM_STYLE0_SHIFT	0
#define PKI_PCAM_TERM_STYLE1_MASK	0xffULL
#define PKI_PCAM_TERM_STYLE1_SHIFT	32

#define PKI_STYLEX_BUF_MB_SIZE_SHIFT	0
#define PKI_STYLEX_BUF_MB_SIZE_MASK	0x1fff
#define PKI_STYLEX_BUF_DIS_WQ_DAT_SHIFT	13
#define PKI_STYLEX_BUF_DIS_WQ_DAT_MASK	0x1
#define PKI_STYLEX_BUF_OPC_MODE_SHIFT	14
#define PKI_STYLEX_BUF_OPC_MODE_MASK	0x3
#define PKI_STYLEX_BUF_LATER_SKIP_SHIFT	16
#define PKI_STYLEX_BUF_LATER_SKIP_MASK	0x3f
#define PKI_STYLEX_BUF_FIRST_SKIP_SHIFT	22
#define PKI_STYLEX_BUF_FIRST_SKIP_MASK	0x3f
#define PKI_STYLEX_BUF_WQE_SKIP_SHIFT	28
#define PKI_STYLEX_BUF_WQE_SKIP_MASK	0x3
#define PKI_STYLEX_BUF_WQE_HSZ_SHIFT	30
#define PKI_STYLEX_BUF_WQE_HSZ_MASK	0x3
#define PKI_STYLEX_BUF_WQE_BEND_SHIFT	32
#define PKI_STYLEX_BUF_WQE_BEND_MASK	0x1

#define PKI_FRM_MINLEN(x)		(0ull | ((x) & 0xffff))
#define PKI_FRM_MAXLEN(x)		(0ull | (((x) & 0xffff) << 16))
#define PKI_BELTYPE(x)			(0ull | ((x) & 0x7))
#define PKI_LTYPE(x)			((x) & 0xffffffff)

#define PKI_SRAM_SZIE			2048

#define PKI_AURA_CFG_BPID_SHIFT		0
#define PKI_AURA_CFG_BPID_MASK		0x3FFULL

#define PKI_ICG_CFG_MAXIPE_USE(x)	((0ull | ((x) & 0x1f)) << 48)
#define PKI_ICG_CFG_CLUSTERS(x)		((0ull | ((x) & 0xf)) << 32)
#define PKI_ICG_CFG_PENA(x)		((0ull | ((x) & 0x1)) << 24)
#define PKI_ICG_CFG_DELAY(x)		((0ull | ((x) & 0xfff)) << 0)

#define PKI_QPG_TBLB_DSTAT_ID_MASK	0x3FFULL
#define PKI_QPG_TBLB_DSTAT_ID_SHIFT	0
#define PKI_QPG_TBLB_STRM_MASK		0xFFULL
#define PKI_QPG_TBLB_STRM_SHIFT		16
#define PKI_QPG_TBLB_ENA_RED_MASK	0x1ULL
#define PKI_QPG_TBLB_ENA_RED_SHIFT	29
#define PKI_QPG_TBLB_ENA_DROP_MASK	0x1ULL
#define PKI_QPG_TBLB_ENA_DROP_SHIFT	28

#define PKI_QPG_TBL_GAURA_MASK		0xFFFULL
#define PKI_QPG_TBL_GAURA_SHIFT		0
#define PKI_QPG_TBL_GRP_BAD_MASK	0x3FFULL
#define PKI_QPG_TBL_GRP_BAD_SHIFT	16
#define PKI_QPG_TBL_GRPTAG_BAD_MASK	0x7ULL
#define PKI_QPG_TBL_GRPTAG_BAD_SHIFT	29
#define PKI_QPG_TBL_GRP_OK_MASK		0x3FFULL
#define PKI_QPG_TBL_GRP_OK_SHIFT	32
#define PKI_QPG_TBL_GRPTAG_OK_MASK	0x7ULL
#define PKI_QPG_TBL_GRPTAG_OK_SHIFT	45
#define PKI_QPG_TBL_PORT_ADD_MASK	0xFFULL
#define PKI_QPG_TBL_PORT_ADD_SHIFT	48

#define PKI_STRM_CFG_GMID_MASK		0xFFFFULL

enum PKI_LTYPE_E {
	PKI_LTYPE_E_NONE	= 0,
	PKI_LTYPE_E_ENET	= 1,
	PKI_LTYPE_E_VLAN	= 2,
	PKI_LTYPE_E_SNAP_PAYLD	= 5,
	PKI_LTYPE_E_ARP		= 6,
	PKI_LTYPE_E_RARP	= 7,
	PKI_LTYPE_E_IP4		= 8,
	PKI_LTYPE_E_IP4_OPT	= 9,
	PKI_LTYPE_E_IP6		= 0xa,
	PKI_LTYPE_E_IP6_OPT	= 0xb,
	PKI_LTYPE_E_IPSEC_ESP	= 0xc,
	PKI_LTYPE_E_IPFRAG	= 0xd,
	PKI_LTYPE_E_IPCOMP	= 0xe,
	PKI_LTYPE_E_TCP		= 0x10,
	PKI_LTYPE_E_UDP		= 0x11,
	PKI_LTYPE_E_SCTP	= 0x12,
	PKI_LTYPE_E_UDP_VXLAN	= 0x13,
	PKI_LTYPE_E_GRE		= 0x14,
	PKI_LTYPE_E_NVGRE	= 0x15,
	PKI_LTYPE_E_GTP		= 0x16,
	PKI_LTYPE_E_UDP_GENEVE	= 0x17,
	PKI_LTYPE_E_SW28	= 0x1c,
	PKI_LTYPE_E_SW29	= 0x1d,
	PKI_LTYPE_E_SW30	= 0x1e,
	PKI_LTYPE_E_SW31	= 0x1f
};

enum PKI_BELTYPE_E {
	PKI_BLTYPE_E_NONE	= 0,
	PKI_BLTYPE_E_MISC	= 1,
	PKI_BLTYPE_E_IP4	= 2,
	PKI_BLTYPE_E_IP6	= 3,
	PKI_BLTYPE_E_TCP	= 4,
	PKI_BLTYPE_E_UDP	= 5,
	PKI_BLTYPE_E_SCTP	= 6,
	PKI_BLTYPE_E_SNAP	= 7
};

#define MAX_PKI_PORTS	64
#define NUM_FRAME_LEN_REG	2

struct pki_port {
	bool	valid;
	bool	has_fcs;
	u32	state;
	u32	pkind;
	u32	init_style;
	u32	qpg_base;
	u32	num_entry;
	u64	shared_mask;
	u16 max_frame_len;
	u16 min_frame_len;
};

struct pkipf_vf {
	struct	octeontx_pf_vf	domain;
	u8	stream_id;
	struct	pki_t	*pki;

	struct	pki_port	bgx_port[MAX_PKI_PORTS];
	struct	pki_port	lbk_port[MAX_PKI_PORTS];

	/* In future if resources are allocated per domain */
	int	max_fstyles;
	int	max_pkinds;
	int	max_bpid;
	int	max_auras;
	int	max_pcams;
	int	max_ipes;
	int	max_cls;
	int	max_stats;
	int	max_dstats;
	int	max_qpgs;
	int	max_pcam_ents;

	int	bpid_base;
	int	fstyle_base;
	int	pknds_base;
	int	stats_base;
	int	dstats_base;
	int	qpg_base;
	int	pcam_ent_base;
};

#define PKI_MAX_VF			32
struct pki_t {
	struct pci_dev		*pdev;
	void __iomem		*reg_base;
	int			id;
	struct msix_entry	*msix_entries;
	struct list_head	list;

	int			max_fstyles;
	int			max_pkinds;
	int			max_bpid;
	int			max_auras;
	int			max_pcams;
	int			max_ipes;
	int			max_cls;
	int			max_stats;
	int			max_dstats;
	int			max_qpgs;
	int			max_pcam_ents;

	int			bpid_base;
	int			fstyle_base;
	int			pknds_base;
	int			stats_base;
	int			dstats_base;
	int			qpg_base;
	int			pcam_ent_base;

	int			total_vfs;
	int			vfs_in_use;
#define PKI_SRIOV_ENABLED	0x1
	u32			flags;
	struct pkipf_vf		vf[PKI_MAX_VF];
};

struct pki_com_s {
	int (*create_domain)(u32, u16, struct octeontx_master_com_t *, void *,
			     struct kobject *kobj, char *g_name);
	int (*free_domain)(u32, u16);
	int (*reset_domain)(u32, u16);
	int (*receive_message)(u32, u16 domain_id,
			       struct mbox_hdr *hdr,
			       union mbox_data *req,
			       union mbox_data *resp, void *mdata);
	int (*add_bgx_port)(u32 node, u16 domain_id,
			    struct octtx_bgx_port *port);
	int (*add_lbk_port)(u32 node, u16 domain_id,
			    struct octtx_lbk_port *port);
};

extern struct pki_com_s pki_com;

/* In Cavium OcteonTX SoCs, all accesses to the device registers are
 * implicitly strongly ordered.
 * So writeq_relaxed() and readq_relaxed() are safe to use
 * with out any memory barriers.
 */

/* Register read/write APIs */
static inline void pki_reg_write(struct pki_t *pki, u64 offset, u64 val)
{
	writeq_relaxed(val, pki->reg_base + offset);
}

static inline u64 pki_reg_read(struct pki_t *pki, u64 offset)
{
	return readq_relaxed(pki->reg_base + offset);
}

int assign_pkind_bgx(struct pkipf_vf *vf, struct octtx_bgx_port *port);
int assign_pkind_lbk(struct pkipf_vf *vf, struct octtx_lbk_port *port);
void init_styles(struct pki_t *pki);

int pki_port_open(struct pkipf_vf *vf, u16 vf_id, mbox_pki_port_t *port_data);
int pki_port_create_qos(struct pkipf_vf *vf, u16 vf_id,
			mbox_pki_qos_cfg_t *qcfg);
int pki_port_modify_qos(struct pkipf_vf *vf, u16 vf_id,
		mbox_pki_mod_qos_t *qcfg);
int pki_port_delete_qos(struct pkipf_vf *vf, u16 vf_id,
		mbox_pki_del_qos_t *qcfg);
int pki_port_start(struct pkipf_vf *vf, u16 vf_id, mbox_pki_port_t *port_data);
int pki_port_stop(struct pkipf_vf *vf, u16 vf_id, mbox_pki_port_t *port_data);
int pki_port_close(struct pkipf_vf *vf, u16 vf_id, mbox_pki_port_t *port_data);
int pki_port_pktbuf_cfg(struct pkipf_vf *vf, u16 vf_id,
			mbox_pki_pktbuf_cfg_t *pcfg);
int pki_port_errchk(struct pkipf_vf *vf, u16 vf_id,
		    mbox_pki_errcheck_cfg_t *cfg);
int pki_port_hashcfg(struct pkipf_vf *vf, u16 vf_id,
		     mbox_pki_hash_cfg_t *cfg);

#endif
