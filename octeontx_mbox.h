/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef OCTEONTX_MBOX_H
#define OCTEONTX_MBOX_H

enum coproc_t {
	NO_COPROC = 0,
	FPA_COPROC = 1,
	SSO_COPROC = 2,
	SSOW_COPROC = 3,
	PKO_COPROC = 4,
	PKI_COPROC = 5,
	BGX_COPROC = 6,
	LBK_COPROC = 7,
	TIM_COPROC = 8
};

/*req messages*/
#define IDENTIFY		0x0

#define FPA_CONFIGSET		0x1
#define FPA_CONFIGGET		0x2
#define FPA_START_COUNT		0x3
#define FPA_STOP_COUNT		0x4
#define FPA_ATTACHAURA		0x5
#define FPA_DETACHAURA		0x6
#define FPA_SETAURALVL		0x7
#define FPA_GETAURALVL		0x8

#define SSO_GETDOMAINCFG	0x1
#define SSO_IDENTIFY		0x2
#define SSO_GET_DEV_INFO	0x3
#define SSO_GET_GETWORK_WAIT	0x4
#define SSO_SET_GETWORK_WAIT	0x5
#define SSO_CONVERT_NS_GETWORK_ITER	0x6
#define SSO_GRP_GET_PRIORITY	0x7
#define SSO_GRP_SET_PRIORITY	0x8
#define SSO_GET_DUMP		0x9

/*resp messages*/
#define MBOX_RET_SUCCESS	0x0
#define MBOX_RET_INVALID	0x2
#define MBOX_RET_INTERNAL_ERR	0x3

/* magic values used for normal and oob data notification */
#define MBOX_TRIGGER_NORMAL	0x00 /* normal msg transport */
#define MBOX_TRIGGER_OOB_RESET	0x01 /* OOB reset request */
#define MBOX_TRIGGER_OOB_RES	0x80 /* OOB response mask */

#define MBOX_MAX_MSG_SIZE	1024

/* Structure used for mbox synchronization
 * This structure sits at the begin of Mbox RAM and is used as main
 * synchronization point for channel communication */
struct mbox_ram_hdr {
	union {
		u64 val;
		struct __attribute__((__packed__)) {
			u8	chan_state : 1;
			u8	coproc : 7;
			u8	msg;
			u8	vfid;
			u8	res_code;
			u16	tag;
			u16	len;
		};
	};
};

struct mbox_hdr {
	u16 vfid;	/* VF idx or PF resource index local to the domain */
	u8 coproc;	/* coprocessor coproc */
	u8 msg;		/* message type */
	u8 oob;		/* out of band data */
	u8 res_code;	/* Functional layer response code */
};

struct mbox {
	void *mbox_base;
	void *ram_base;
	size_t ram_size;
	struct mbox_ram_hdr hdr_party; /* last header received from party channel */
	u16 tag_own; /* last tag which was written to own channel */
	u8 chan_own; /* of wchich channel direction we are the owner */
	u8 oob; /* OOB in progress */
};

typedef enum {
	MBOX_SIDE_PF = 0,
	MBOX_SIDE_VF = 1
} mbox_side_t;

/* This function initializes the mbox module and communication channel.
 * This function should be called before any other mbox function calls.
 *
 * @param sso_base Bar base address for SSO
 * @param ram_base Ram base for extended msg
 * @param ram_size Ram size for extended msg (must be power of 2)
 * @param pf Working mode for mastering of the correct channel , PF - true, VF - false
 *
 * @note The excact actions taken by this function depends on excact protocol
 *       version implemented. Refer to git changeset or source code file for
 *       detailed desctiption.
 */
void mbox_init(
	struct mbox *mbox,
	void *sso_base,
	void *ram_base,
	size_t ram_size,
	mbox_side_t side);

/* Function called by sender (master) to perform whole send-recv transaction.
 * Function bloks until msg received or timeout.
 *
 * @param hdr Common message fields
 * @param txmsg pointer to msg body to be send out
 * @param txsize length of req msg to be send out
 * @param rxmsg Pointer to buffer for msg body to be recv warning: this buffer
 *        need to be large enough. Size of it need to be stored in rxsize
 *        param
 * @param rxsize length of buffer for resp msg which could be recv. If the
 *        given size is smaller than received message body, the message will be
 *        truncated
 *
 * @return length of received message (can be 0), <0 in case of error
 *
 * @note in case of error, channel will reset channel to initial state
 */
int mbox_send(
	struct mbox *mbox,
	struct mbox_hdr *hdr,
	const void *txmsg,
	size_t txsize,
	void *rxmsg,
	size_t rxsize);

/* Function called by slave (receiver) to fetch the request from master (sender).
 *
 * @param hdr Common message fields
 * @param rxmsg pointer to buffer for msg body to be recv warning: this buffer
 *        need to be large enough. Size of it need to be stored in size
 *        param
 * @param rxsize length of buffer for resp msg which could be recv. If the
 *        given size is smaller than received message body, the message will be
 *        truncated
 *
 * @return length of received message (can be 0),
 *         <0 in case of error or there was no message in mbox
 *
 * @note in case of error, function does not reset the channel
 */
int mbox_receive(
	struct mbox *mbox,
	struct mbox_hdr *hdr,
	void *rxmsg,
	size_t rxsize);

/* Function called by slave (receiver) to send the response to master (initial sender)
 *
 * @param res_code Functional layer response code.
 * @param txmsg pointer to msg body to be send out
 * @param txsize length of req msg to be send out. The length of the message
 *        cannot exceed the mbox ram buffer or the message will be truncated
 *
 * @return 0 in case response msg was successfully transmited
 *	   != 0 in case of error or there was detected timeout for current
 *	   trasaction
 *
 * @note in case of error, function does not reset the channel
 */
int mbox_reply(
	struct mbox *mbox,
	u8 res_code,
	const void *txmsg,
	size_t txsize);


struct __attribute__((__packed__)) gen_req {
	u32	value;
};

struct __attribute__((__packed__)) idn_req {
	u8	domain_id;
};

struct __attribute__((__packed__)) gen_resp {
	u16	domain_id;
	u16	vfid;
};

struct __attribute__((__packed__)) dcfg_resp {
	u8	sso_count;
	u8	ssow_count;
	u8	fpa_count;
	u8	pko_count;
	u8	tim_count;
	u8	net_port_count;
	u8	virt_port_count;
};

/* FPA specific */
struct mbox_fpa_cfg {
	int	aid;
	u64	pool_cfg;
	u64	pool_stack_base;
	u64	pool_stack_end;
	u64	aura_cfg;
};

/* SSOW */
struct mbox_ssow_identify {
	u16	domain_id;
	u16	subdomain_id;
};
/* FIXME: This union is temporary until we agree to move all messages to RAM */
union mbox_data {
	u64			data;
	struct gen_req		gen_req;
	struct gen_resp		gen_resp;
	struct idn_req		id;
	struct dcfg_resp	cfg;

	//TODO: warning Remove resp_hdr
	struct gen_resp		resp_hdr;
};

/*----------------------------------------------------------------------------*/
/* BGX messages:                                                              */
/*----------------------------------------------------------------------------*/
/* Message IDs for BGX_COPROC */
#define MBOX_BGX_PORT_OPEN 0
#define MBOX_BGX_PORT_CLOSE 1
#define MBOX_BGX_PORT_START 2
#define MBOX_BGX_PORT_STOP 3
#define MBOX_BGX_PORT_GET_CONFIG 4
#define MBOX_BGX_PORT_GET_STATUS 5
#define MBOX_BGX_PORT_GET_STATS 6
#define MBOX_BGX_PORT_CLR_STATS 7
#define MBOX_BGX_PORT_GET_LINK_STATUS 8
#define MBOX_BGX_PORT_SET_PROMISC 9
#define MBOX_BGX_PORT_SET_MACADDR 10
#define MBOX_BGX_PORT_SET_BP 11
#define MBOX_BGX_PORT_SET_BCAST 12
#define MBOX_BGX_PORT_SET_MCAST 13

/* BGX port configuration parameters: */
typedef struct mbox_bgx_port_conf {
	u8 enable; /* 1 = port activated, 0 = port is idle.*/
	u8 promisc; /* 1 = enabled, 0 = disabled */
	u8 bpen; /* 1 = backpressure enabled, 0 = disabled.*/
	u8 macaddr[6]; /* MAC address.*/
	u8 fcs_strip; /* 1 = enabled, 0 = disabled (BGX[]_CMR_GLOBAL_CONFIG[fcs_strip]).*/
	u8 bcast_mode; /* 1 = enabled, 0 = disabled (BGX[]_CMR[]_RX_DMAC_CTL[bcst_mode]).*/
	u8 mcast_mode; /* BGX[]_CMR[]_RX_DMAC_CTL[mcst_mode].*/
	u8 node; /* CPU node */
	u16 base_chan; /* Base channel (PKI_CHAN_E) */
	u16 num_chans; /* Number of channels */
	/* Diagnostics support: */
	u8 bgx; /* BGX number */
	u8 lmac; /* LMAC number */
	u8 mode; /* As shown in BGX[]_CMR[]_CONFIG[lmac_type]: SGMII, XAUI, ... */
	u8 pkind; /* PF value of PKIND (PKI port: BGX[]_CMR[]_RX_ID_MAP[pknd]).*/
} mbox_bgx_port_conf_t;

/* BGX port status: */
typedef struct mbox_bgx_port_status {
	u8 link_up; /* 1 = link is up, 0 = link is down. */
	u8 bp; /* 1 = LMAC is backpressured, 0 = no backpressure. */
	/* TODO: Add other read-only device parameters.*/
} mbox_bgx_port_status_t;

/* BGX port statistics: */
typedef struct mbox_bgx_port_stats {
	u64 rx_packets;	    /* Total packets received. */
	u64 tx_packets;	    /* Total packets transmitted. */
	u64 rx_bytes;	    /* Total bytes received. */
	u64 tx_bytes;	    /* Total bytes transmitted. */
	u64 rx_errors;	    /* Bad packets received. */
	u64 tx_errors;	    /* Packet transmit problems. */
	u64 rx_dropped;	    /* No buffer space. */
	u64 tx_dropped;	    /* No buffer space. */
	u64 multicast;	    /* Multicast packets received. */
	u64 collisions;

	/* Detailed receive errors. */
	u64 rx_length_errors;
	u64 rx_over_errors;	/* Receiver ring buff overflow. */
	u64 rx_crc_errors;		/* Recved pkt with crc error. */
	u64 rx_frame_errors;	/* Recv'd frame alignment error. */
	u64 rx_fifo_errors;	/* Recv'r fifo overrun . */
	u64 rx_missed_errors;	/* Receiver missed packet. */

	/* Detailed transmit errors. */
	u64 tx_aborted_errors;
	u64 tx_carrier_errors;
	u64 tx_fifo_errors;
	u64 tx_heartbeat_errors;
	u64 tx_window_errors;

	/* Extended statistics based on RFC2819. */
	u64 rx_1_to_64_packets;
	u64 rx_65_to_127_packets;
	u64 rx_128_to_255_packets;
	u64 rx_256_to_511_packets;
	u64 rx_512_to_1023_packets;
	u64 rx_1024_to_1522_packets;
	u64 rx_1523_to_max_packets;

	u64 tx_1_to_64_packets;
	u64 tx_65_to_127_packets;
	u64 tx_128_to_255_packets;
	u64 tx_256_to_511_packets;
	u64 tx_512_to_1023_packets;
	u64 tx_1024_to_1522_packets;
	u64 tx_1523_to_max_packets;

	u64 tx_multicast_packets;
	u64 rx_broadcast_packets;
	u64 tx_broadcast_packets;
	u64 rx_undersized_errors;
	u64 rx_oversize_errors;
	u64 rx_fragmented_errors;
	u64 rx_jabber_errors;
} mbox_bgx_port_stats_t;

/*----------------------------------------------------------------------------*/
/* LBK messages:                                                              */
/*----------------------------------------------------------------------------*/
/* Message IDs for LBK_COPROC */
#define MBOX_LBK_PORT_OPEN 0
#define MBOX_LBK_PORT_CLOSE 1
#define MBOX_LBK_PORT_START 2
#define MBOX_LBK_PORT_STOP 3
#define MBOX_LBK_PORT_GET_CONFIG 4
#define MBOX_LBK_PORT_GET_STATUS 5
#define MBOX_LBK_PORT_GET_STATS 6
#define MBOX_LBK_PORT_CLR_STATS 7
#define MBOX_LBK_PORT_GET_LINK_STATUS 8

/* LBK port configuration parameters: */
typedef struct mbox_lbk_port_conf {
	u8 enabled; /* 1 = activated, 0 = idle.*/
	u8 node;
	u16 base_ichan; /* Base input channel (PKI_CHAN_E) */
	u16 num_ichans; /* Number of input channels */
	u16 base_ochan; /* Base output channel (PKI_CHAN_E) */
	u16 num_ochans; /* Number of output channels */
	/* Diagnostics support: */
	u8 ilbk, olbk; /* Ingress and egress LBK numbers */
	u8 pkind; /* PKI port (PF value).*/
} mbox_lbk_port_conf_t;

/* LBK port status: */
typedef struct mbox_lbk_port_status {
	int link_up; /* 1 = link is up, 0 = link is down. */
	u8 chan_oflow; /* Channel overflow */
	u8 chan_uflow; /* Channel underflow */
	u8 data_oflow; /* Packet data overflow */
	u8 data_uflow; /* Packet data underflow */
} mbox_lbk_port_status_t;

/* LBK port statistics: */
typedef struct mbox_lbk_port_stats {
	u64 rx_octets;
	u64 rx_frames;
	u64 tx_octets;
	u64 tx_frames;
} mbox_lbk_port_stats_t;


/*
 * SSO Message struct
 **/
struct mbox_sso_get_dev_info {
	u64 min_getwork_wait_ns;/* minimum getwork wait in ns [out] */
	u64 max_getwork_wait_ns;/* maximum getwork wait in ns [out] */
	u32 max_events; 	/* maximum xaq ddr event entries [out] */
};

struct mbox_sso_getwork_wait {
	u64 wait_ns; 		/* get_work wait in ns [in] [out] */
};


struct mbox_sso_convert_ns_getworks_iter {
	u64 wait_ns; 		/* ns [in] */
	u32 getwork_iter; 	/* get_work iterations for the
				 * given wait_ns [out] */
};


struct mbox_sso_grp_priority {
	u8 vhgrp_id;		/* vhgrp id, PF driver is reposible for
				 *  convertig to physical sso grp id [in] */
				/* filelds of SSO_GRP(0..63)_PRI */
	u8 wgt_left;  		/* [out] */
	u8 weight;    		/* [in] [out] */
	u8 affinity;  		/* [in] [out] */
	u8 pri;       		/* [in] [out] */
};


struct mbox_sso_get_dump {
	size_t len;			/* [out] */
	u8 buf[MBOX_MAX_MSG_SIZE]; 	/* [out] */
};

/*----------------------------------------------------------------------------*/
/* TIM messages:                                                              */
/*----------------------------------------------------------------------------*/
#define MBOX_TIM_IDENT_CODE(__dom, __subdom) \
	((((u64)(__subdom) << 16) | (__dom)) << 7)

#define MBOX_TIM_DOM_FROM_IDENT(__ident) \
	(((u64)(__ident) >> 7) & 0xFFFFull)

#define MBOX_TIM_SDOM_FROM_IDENT(__ident) \
	(((u64)(__ident) >> (7 + 16)) & 0xFFFFull)

/* Message IDs for TIM_COPROC */
/* #define IDENTIFY              0 */
#define MBOX_TIM_DEV_INFO_GET    1 /* Read TIM device config and status.*/
#define MBOX_TIM_RING_INFO_GET   2 /* Read TIM ring config and status.*/
#define MBOX_TIM_RING_CONFIG_SET 3 /* Write ring configuration */

/* TIM device configuration and status parameters: */
struct __attribute__((__packed__)) mbox_tim_dev_info {
	u64 eng_active[4]; /* TIM_ENGINE_ACTIVE register images */
	u64 tim_clk_freq;  /* TIM device base clock (SCLK) rate */
};

/* TIM ring configuration and status parameters: */
struct __attribute__((__packed__)) mbox_tim_ring_info {
	u8 node; /* CPU node/TIM device this ring resides on.*/
	u64 ring_late; /* TIM_VRING_LATE register image */
};

/* TIM ring configuration and status parameters: */
struct __attribute__((__packed__)) mbox_tim_ring_conf {
	u64 ctl0; /* TIM_RING_CTL0 register image */
	u64 ctl1; /* TIM_RING_CTL1 register image */
	u64 ctl2; /* TIM_RING_CTL2 register image */
};

/*----------------------------------------------------------------------------*/
/* PKI messages:                                                              */
/*----------------------------------------------------------------------------*/
/* Message IDs for PKI_COPROC */
/* Message 0-7 are privileged messages applies to pkind */
#define MBOX_PKI_GLOBAL_CONFIG			0

/* alloc and assign initial syle, 1st release port not sharing style
 * set style to drop all packets, style_cfg->DROP =1*/
#define MBOX_PKI_PORT_OPEN			1
/* set port to start receive packets style_cfg->DROP=0 */
#define MBOX_PKI_PORT_START 			2
/* set style of this port to drop all packets style_cfg->DROP =1*/
#define MBOX_PKI_PORT_STOP   			3
/* Free the style/qpg/pcam entries allocated to this port, if not shared. Set to DROP style*/
#define MBOX_PKI_PORT_CLOSE			4
#define MBOX_PKI_PORT_CONFIG			5
#define MBOX_PKI_PORT_OPT_PARSER_CONFIG		6
#define MBOX_PKI_PORT_CUSTOM_PARSER_CONFIG	7
#define MBOX_PKI_PORT_PKTBUF_CONFIG		8
#define MBOX_PKI_PORT_HASH_CONFIG		9
#define MBOX_PKI_PORT_ERRCHK_CONFIG		10
/* alloc consecutive number of qpg entry and setup passed parameters.
   set style qpg_base to allocated entries base, 1st version don't allow sharing but later
   check if qpg entry with same parameters already exist and use it and mark it shared */
#define MBOX_PKI_PORT_CREATE_QOS 		11 /* sets up the sso grp, aura etc to be used with that flow */
/* Modify offset from the qpg_base */
#define MBOX_PKI_PORT_MODIFY_QOS		12 /* Modifies one indexed qos entry */
/* Delet the complete qpg entries attached to this port */
#define MBOX_PKI_PORT_DELETE_QOS		13 /* Modifies one indexed qos entry */
/* Enable/disable RSS by setting qpg_grptag in all the qpg entries */
#define MBOX_PKI_PORT_ENABLE_RSS		14
#define MBOX_PKI_PORT_PKTDROP_CONFIG		15
#define MBOX_PKI_PORT_WQE_GEN_CONFIG		16
#define MBOX_PKI_BACKPRESSURE_CONFIG		17
#define MBOX_PKI_PORT_GET_STATS			18
#define MBOX_PKI_PORT_RESET_STATS		19
#define MBOX_PKI_GET_PORT_CONFIG		20
#define MBOX_PKI_GET_PORT_QOS_CONFIG		22

/* pki pkind parse mode */
enum  {
	MBOX_PKI_PARSE_LA_TO_LG = 0,	/* parse LA(L2) to LG */
	MBOX_PKI_PARSE_LB_TO_LG = 1,	/* parse LB(custom) to LG */
	MBOX_PKI_PARSE_LC_TO_LG = 3,	/* parse LC(L3) to LG */
	MBOX_PKI_PARSE_LG = 0x3f,	/* parse LG */
	MBOX_PKI_PARSE_NOTHING = 0x7f	/* parse nothing */
};

/* pki port config */
typedef struct mbox_pki_port_type {
	u8 port_type;
} mbox_pki_port_t;

/* pki port config */
typedef struct mbox_pki_port_cfg {
	struct { /* modify mask 1=modify 0=dont modify*/
		u8 fcs_pres:1;
		u8 fcs_skip:1;
		u8 parse_mode:1;
		u8 mpls_parse:1;
		u8 inst_hdr_parse:1;
		u8 fulc_parse:1;
		u8 dsa_parse:1;
		u8 hg2_parse:1;
		u8 hg_parse:1;
	} mmask;
	u8 fcs_pres;	/* If FCS present on the packets received on this port
			   1=present : 0=not present */
	u8 fcs_skip;	/* bytes to skip from front of packet to first byte covered by fcs */
	u8 parse_mode;	/* initial parse mode*/
	u8 mpls_parse;
	u8 inst_hdr_parse;
	u8 fulc_parse;
	u8 dsa_parse;
	u8 hg2_parse;
	u8 hg_parse;
} mbox_pki_prt_cfg_t;


/* pki Flow/style packet buffer config */
typedef struct mbox_pki_port_pktbuf_cfg {
	struct { /* modify mask  1=modify 0=no moidfy*/
		u16 f_mbuff_size:1;
		u16 f_wqe_skip:1;
		u16 f_first_skip:1;
		u16 f_later_skip:1;
		u16 f_pkt_outside_wqe:1;
		u16 f_wqe_endian:1;
		u16 f_cache_mode:1;
	} mmask;
	u16 mbuff_size;	/* total buffer size including first skip or later skip */
	u16 wqe_skip;	/* number of bytes to skip from top of buffer before start writing WQE word0 */
	u16 first_skip;	/* number of bytes to skip from top of buffer before start of writing next_pointer */
	u16 later_skip;	/* number of bytes to skip from top of not first buffer before next pointer */
	u8 pkt_outside_wqe;	/* wqe and data in separate buffers 0=same buffer 1=separate bugger for wqe and data*/
	u8 wqe_endian;	/* wqe header and pkt_buflink_s endianess. 1: big endian 0: little endian */
	u8 cache_mode;  /* select the L2C write */
} mbox_pki_pktbuf_cfg_t;

/* pki flow/style tag config */
typedef struct mbox_pki_port_hash_cfg {
	u32 tag_slf:1;
	u32 tag_sle:1;
	u32 tag_sld:1;
	u32 tag_slc:1;
	u32 tag_dlf:1;
	u32 tag_dle:1;
	u32 tag_dld:1;
	u32 tag_dlc:1;
	u32 tag_prt:1;
	u32 tag_vlan0:1;
	u32 tag_vlan1:1;
	u32 tag_ip_pctl:1;
	u32 tag_sync:1;
	u32 tag_spi:1;
	u32 tag_gtp:1;
	u32 tag_vni:1;
} mbox_pki_hash_cfg_t;

/* pki flow/style errcheck config */
typedef struct mbox_pki_port_errcheck_cfg {
	struct { /* modify mask 1=modify 0=dont modify*/
		u32 f_ip6_udp_opt:1;
		u32 f_lenerr_en:1;
		u32 f_maxerr_en:1;
		u32 f_minerr_en:1;
		u32 f_fcs_chk:1;
		u32 f_fcs_strip:1;
		u32 f_len_lf:1;
		u32 f_len_le:1;
		u32 f_len_ld:1;
		u32 f_len_lc:1;
		u32 f_csum_lf:1;
		u32 f_csum_le:1;
		u32 f_csum_ld:1;
		u32 f_csum_lc:1;
		u32 f_min_frame_len;
		u32 f_max_frame_len;
	} mmask;
	u64 ip6_udp_opt:1; /**< IPv6/UDP checksum is optional. IPv4 allows
						* an optional UDP checksum by sending the all-0s
						* patterns. IPv6 outlaws this and the spec says to always check UDP checksum.
						0 = Spec compliant, do not allow optional code.
						1 = Treat IPv6 as IPv4; */
	u64 lenerr_en:1; /**< L2 length error check enable. Check if frame was received with L2 length error. */
	u64 maxerr_en:1; /**< Max frame error check enable. */
	u64 minerr_en:1; /**< Min frame error check enable. */
	u64 fcs_chk:1; /** if fcs_pres =0 make fcs_chk =0 too*/
	u64 fcs_strip:1; /** if fcs_pres =0 make fcs_strip=0 too*/
	u64 len_lf:1; /**< Check length of Layer F. */
	u64 len_le:1; /**< Check length of Layer E. */
	u64 len_ld:1; /**< Check length of Layer D. */
	u64 len_lc:1; /**< Check length of Layer C. */
	u64 csum_lf:1; /**< Compute checksum on Layer F. */
	u64 csum_le:1; /**< Compute checksum on Layer E. */
	u64 csum_ld:1; /**< Compute checksum on Layer D. */
	u64 csum_lc:1; /**< Compute checksum on Layer C. */
	u64 min_frame_len;
	u64 max_frame_len;
} mbox_pki_errcheck_cfg_t;

/* CACHE MODE*/
enum {
	MBOX_PKI_OPC_MODE_STT = 0LL,		/* All blocks write through DRAM,*/
	MBOX_PKI_OPC_MODE_STF = 1LL,		/* All blocks into L2 */
	MBOX_PKI_OPC_MODE_STF1_STT = 2LL,	/* 1st block L2, rest DRAM */
	MBOX_PKI_OPC_MODE_STF2_STT = 3LL	/* 1st, 2nd blocks L2, rest DRAM */
};

/**
 * Tag type definitions
 */
/* SSO TAG TYPES*/
enum {
	MBOX_SSO_TAG_TYPE_ORDERED = 0L,	/**< Tag ordering is maintained */
	MBOX_SSO_TAG_TYPE_ATOMIC = 1L,	/**< Tag ordering is maintained, and at most one PP has the tag */
	MBOX_SSO_TAG_TYPE_UNTAGGED = 2L,
	MBOX_SSO_TAG_TYPE_EMPTY = 3L	/**< A tag switch to NULL, and there is no space reserved in POW */
};

/* PKI QPG QOS*/
enum {
	MBOX_PKI_QPG_QOS_NONE = 0,
	MBOX_PKI_QPG_QOS_VLAN,
	MBOX_PKI_QPG_QOS_MPLS,
	MBOX_PKI_QPG_QOS_DSA_SRC,
	MBOX_PKI_QPG_QOS_DIFFSERV,
	MBOX_PKI_QPG_QOS_HIGIG,
};

#if 0
/* PKI DROP POLICY*/
enum {

};/* TODO */
#endif

struct mbox_pki_qos_entry {
	u16 port_add;
	u16 ggrp_ok;
	u16 ggrp_bad;
	u16 gaura;
};

/* hardcoded TODO */
#define MBOX_PKI_MAX_QOS_ENTRY 64

/* pki flow/style enable qos */
typedef struct mbox_pki_port_create_qos {
	u8 qpg_qos;
	u8 num_entry; /* number of qos entries to create */
	u8 tag_type; /* All the queues have same tag type */
	u8 drop_policy; /* All the queues have same drop policy */
	struct mbox_pki_qos_entry qos_entry[MBOX_PKI_MAX_QOS_ENTRY];
} mbox_pki_qos_cfg_t;

/* pki flow/style enable qos */
typedef struct mbox_pki_port_modify_qos_entry {
	u16 index;
	struct { /* modify mask 1=modify 0=don't modify*/
		u8 f_port_add:1;
		u8 f_grp_ok:1;
		u8 f_grp_bad:1;
		u8 f_gaura:1;
	} mmask;
	struct mbox_pki_qos_entry qos_entry;
} mbox_pki_mod_qos_t;

/* pki flow/style enable rss
 *
 * If this message is received before create_qos, store the number of queues in
 * the database and when enable_qos received, program it same for all the
 * entries in first release.
 */
typedef struct mbox_pki_port_enable_rss {
	u8 en_dis;	/* 1=enable 0=disable*/
	u8 num_queues;
} mbox_pki_rss_cfg_t;

#endif
