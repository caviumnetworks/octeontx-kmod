/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef OCTEONTX_H
#define OCTEONTX_H

#include <linux/netdevice.h>
#include <linux/ioctl.h>

#include "octeontx_mbox.h"

#define OCTTX_MAX_NODES	1 /* Maximum number of CPU devices/nodes */

#define get_gmid(x) (x)

struct octeontx_pf_vf {
	bool			in_use;
	u16			domain_id;
	u16			subdomain_id;
	u32			gmid;

	void __iomem		*reg_base;
	struct octeontx_master_com_t *master;
	void			*master_data;
};

struct octeontx_master_com_t {
	int (*send_message)(struct mbox_hdr *hdr,
			    union mbox_data *req,
			    union mbox_data *resp,
			    void *master_data,
			    void *add_data);
	int (*receive_message)(struct mbox_hdr *hdr,
			       union mbox_data *req,
			       union mbox_data *resp,
			       void *master_data,
			       void *add_data);
	int (*reset_domain)(void *master_data);
};

struct wqe_s {
	u64 work0;
	u64 *work1;
};

#define OCTTX_IOC_MAGIC	0xF2

/* THUNDERX SMC definitons */
/* X1 - gpio_num, X2 - sp, X3 - cpu, X4 - ttbr0 */ 
#define THUNDERX_INSTALL_GPIO_INT       0x43000801
/* X1 - gpio_num */
#define THUNDERX_REMOVE_GPIO_INT        0x43000802

struct intr_hand {
	u64	mask;
	char	name[50];
	u64	coffset;
	u64	soffset;
	irqreturn_t (*handler)(int, void *);
};

struct octtx_gpio {
	uint64_t ttbr;
	uint64_t isr_base;
	uint64_t sp;
	int in_use;
	uint64_t cpu;
	uint64_t gpio_num;
};

struct octtx_gpio_usr_data {
	uint64_t	isr_base;
	uint64_t	sp;
	uint64_t	cpu;
	uint64_t	gpio_num;
};

#define OCTTX_IOC_SET_GPIO_HANDLER	_IOW(OCTTX_IOC_MAGIC, 1, struct octtx_gpio_usr_data) 
#define OCTTX_IOC_CLR_GPIO_HANDLER	_IOW(OCTTX_IOC_MAGIC, 2, int)

enum domain_type {
	APP_NET = 0,
	HOST_NET
};

/* Domain network (BGX) port */
#define OCTTX_MAX_BGX_PORTS 16 /* Maximum BGX ports per System */

/* Same as in BGX_CMR_CONFIG[lmac_type] */
#define OCTTX_BGX_LMAC_TYPE_SGMII  0
#define OCTTX_BGX_LMAC_TYPE_XAUI   1
#define OCTTX_BGX_LMAC_TYPE_RXAUI  2
#define OCTTX_BGX_LMAC_TYPE_10GR   3
#define OCTTX_BGX_LMAC_TYPE_40GR   4
#define OCTTX_BGX_LMAC_TYPE_QSGMII 6

struct octtx_bgx_port {
	struct list_head list;
	int	domain_id;
	int	dom_port_idx; /* Domain-local index of BGX port */
	int	glb_port_idx; /* System global index of BGX port */
	int	node; /* CPU node */
	int	bgx; /* Node-local BGX device index */
	int	lmac; /* BGX-local port/LMAC number/index */
	int	lmac_type; /* OCTTX_BGX_LMAC_TYPE_nnn */
	int	base_chan; /* Node-local base channel (PKI_CHAN_E) */
	int	num_chans;
	int	pkind; /* PKI port number */
	int	link_up; /* Last retrieved link status */
};

/* Domain internal (LBK) port */
#define OCTTX_MAX_LBK_PORTS 2 /* Maximum LBK ports per System */

struct octtx_lbk_port {
	struct list_head list;
	int	domain_id;
	int	dom_port_idx; /* Domain-local index of LBK port */
	int	glb_port_idx; /* System global index of LBK port */
	int	node; /* CPU node */
	int	ilbk; /* Node-local index of ingress LBK device */
	int	olbk; /* Node-local index of egress LBK device */
	int	ilbk_base_chan; /* Node-local base channel (PKI_CHAN_E) */
	int	ilbk_num_chans;
	int	olbk_base_chan; /* Node-local base channel (PKI_CHAN_E) */
	int	olbk_num_chans;
	int	pkind; /* PKI port number */
	void	*vnic; /* NIC port descriptor */
};

/* GPIO related defintions */

#endif

