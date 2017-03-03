/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/device.h>

#include "octeontx.h"
#include "octeontx_mbox.h"
#include "fpa.h"
#include "fpa.h"
#include "sso.h"

#define DRV_NAME "octeontx"
#define DRV_VERSION "0.1"
#define DEVICE_NAME "octtx-ctr"
#define CLASS_NAME "octeontx-rm"

static struct cdev *octtx_cdev;
static struct device *octtx_device;
static struct class *octtx_class;
static dev_t octtx_dev;

static atomic_t gbl_domain_id = ATOMIC_INIT(4);

static struct fpapf_com_s *fpapf;
static struct ssopf_com_s *ssopf;
static struct ssowpf_com_s *ssowpf;

struct delayed_work dwork_reset;
struct workqueue_struct *check_link;
struct workqueue_struct *reset_domain;

struct octtx_domain {
	struct list_head list;
	int node;
	int domain_id;
	int setup;
	int type;
	char name[1024];

	int pko_vf_count;
	int fpa_vf_count;
	int sso_vf_count;
	int ssow_vf_count;
	int tim_vf_count;

	u64 aura_set;
	u64 grp_mask;

	int num_bgx_ports;
	int num_lbk_ports;
	struct octtx_bgx_port bgx_port[OCTEONTX_MAX_BGX_PORTS];
	struct octtx_lbk_port lbk_port[OCTEONTX_MAX_LBK_PORTS];

	struct attribute_group sysfs_group;
	struct device_attribute dom_attr;
};

static DEFINE_SPINLOCK(octeontx_domains_lock);
static LIST_HEAD(octeontx_domains);

MODULE_AUTHOR("Tirumalesh Chalamarla");
MODULE_DESCRIPTION("Cavium OCTEONTX coprocessor management Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);

int octeontx_create_domain(const char *name, int type,
		int sso_count, int fpa_count, int ssow_count,
		int pko_count, int pki_count, int tim_count,
		int bgx_count, int lbk_count, const long int *bgx_port,
		const long int *lbk_port);

static ssize_t octtx_create_domain_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	return snprintf(buf, PAGE_SIZE, "0\n");
}

static ssize_t octtx_create_domain_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf,
					size_t count)
{
	int ret = 0;
	char *start;
	char *end;
	char *name;
	char *temp;
	long int type;
	long int sso_count = 0;
	long int fpa_count = 0;
	long int ssow_count = 0;
	long int pko_count = 0;
	long int tim_count = 0;
	long int bgx_count = 0;
	long int lbk_count = 0;
	long int lbk_port[OCTEONTX_MAX_LBK_PORTS];
	long int bgx_port[OCTEONTX_MAX_BGX_PORTS];

	end = kzalloc(PAGE_SIZE, GFP_KERNEL);
	memcpy(end, buf, count);

	start = strsep(&end, ";");
	if (!start)
		goto error;

	name = strsep(&start, ":");
	if (!start)
		type = APP_NET;
	else if (kstrtol(start, 10, &type))
		goto error;

	for (;;) {
		start = strsep(&end, ";");
		if (!start)
			break;
		if (!*start)
			continue;

		if (!strncmp(start, "ssow", sizeof("ssow") - 1)) {
			temp = strsep(&start, ":");
			if (kstrtol(start, 10, &ssow_count))
				goto error;
		} else if (!strncmp(start, "fpa", sizeof("fpa") - 1)) {
			temp = strsep(&start, ":");
			if (kstrtol(start, 10, &fpa_count))
				goto error;
		} else if (!strncmp(start, "sso", sizeof("sso") - 1)) {
			temp = strsep(&start, ":");
			if (kstrtol(start, 10, &sso_count))
				goto error;
		} else if (!strncmp(start, "pko", sizeof("pko") - 1)) {
			temp = strsep(&start, ":");
			if (kstrtol(start, 10, &pko_count))
				goto error;
		} else if (!strncmp(start, "pki", sizeof("pki") - 1)) {
			continue;
		} else if (!strncmp(start, "tim", sizeof("tim") - 1)) {
			temp = strsep(&start, ":");
			if (kstrtol(start, 10, &tim_count))
				goto error;
		} else if (!strncmp(start, "net", sizeof("net") - 1)) {
			temp = strsep(&start, ":");
			if (kstrtol(start, 10, &bgx_port[bgx_count]))
				goto error;
			bgx_count++;
		} else if (!strncmp(start, "lbk", sizeof("lbk") - 1)) {
			temp = strsep(&start, ":");
			if (kstrtol(start, 10, &lbk_port[lbk_count]))
				goto error;
			lbk_count++;
		} else {
			goto error;
		}
	}

	ret = octeontx_create_domain(name, type, sso_count, fpa_count,
			ssow_count, pko_count, 1, tim_count, bgx_count,
			lbk_count, (const long int *)bgx_port,
			(const long int *)lbk_port);
	if (ret)
		goto error;

	return count;
error:
	dev_err(dev, "Command failed..\n");
	return count;
}

static DEVICE_ATTR(create_domain, 0600, octtx_create_domain_show,
		octtx_create_domain_store);

static struct attribute *octtx_attrs[] = {
	&dev_attr_create_domain.attr,
	NULL
};

static struct attribute *octtx_def_attrs[] = {
	NULL
};

static struct attribute_group octtx_attr_group = {
	.name = "octtx_attr",
	.attrs = octtx_attrs,
};

int octtx_sysfs_init(struct device *octtx_device)
{
	int ret;

	ret = sysfs_create_group(&octtx_device->kobj, &octtx_attr_group);
	if (ret < 0) {
		dev_err(octtx_device, " create_domain sysfs failed\n");
		return ret;
	}
	return 0;
}

void octtx_sysfs_remove(struct device *octtx_device)
{
	kobject_put(&octtx_device->kobj);
}

static int octtx_master_receive_message(struct mbox_hdr *hdr,
					union mbox_data *req,
					union mbox_data *resp,
					void *master_data,
					void *add_data)
{
	struct octtx_domain *domain = master_data;

	switch (hdr->coproc) {
	case FPA_COPROC:
		fpapf->receive_message(0, domain->domain_id, hdr, req, resp,
				       add_data);
		break;
	case BGX_COPROC:
	case LBK_COPROC:
	case PKO_COPROC:
	case TIM_COPROC:
	case SSOW_COPROC:
	case SSO_COPROC:
	case PKI_COPROC:
	default:
		dev_err(octtx_device, "invalid mbox message\n");
		hdr->res_code = MBOX_RET_INVALID;
		break;
	}
	return 0;
}

static struct octeontx_master_com_t octtx_master_com = {
	.receive_message = octtx_master_receive_message,
};

void octeontx_remove_domain(int node, int domain_id)
{
	struct octtx_domain *domain = NULL;
	struct octtx_domain *curr;

	spin_lock(&octeontx_domains_lock);
	list_for_each_entry(curr, &octeontx_domains, list) {
		if (curr->domain_id == domain_id && curr->node == node)
			domain = curr;
	}

	if (domain) {
		list_del(&domain->list);
		kfree(domain);
	}
	spin_unlock(&octeontx_domains_lock);

	ssopf->free_domain(node, domain_id);
	ssowpf->free_domain(node, domain_id);
	fpapf->free_domain(node, domain_id);
}

static ssize_t octtx_domain_id_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	struct octtx_domain *domain;

	domain = container_of(attr, struct octtx_domain, dom_attr);

	return snprintf(buf, PAGE_SIZE, "%d\n", domain->domain_id);
}

int octeontx_create_domain(const char *name, int type,
		int sso_count, int fpa_count, int ssow_count,
		int pko_count, int pki_count, int tim_count,
		int bgx_count, int lbk_count, const long int *bgx_port,
		const long int *lbk_port)
{
	int node = 0;
	struct octtx_domain *domain;
	u16 domain_id;
	int ret = -EINVAL;
	void *ssow_ram_mbox_addr = NULL;

	list_for_each_entry(domain, &octeontx_domains, list) {
		if (!strcmp(name, domain->name))
			return -EEXIST;
	}
	/*get DOMAIN ID */
	domain_id = atomic_add_return(1, &gbl_domain_id);
	domain_id -= 1;

	domain = kzalloc(sizeof(struct octtx_domain), GFP_KERNEL);
	if(!domain)
		return -ENOMEM;

	domain->node = node;
	domain->domain_id = domain_id;
	memcpy(domain->name, name, strlen(name));
	domain->type = type;

	domain->sysfs_group.name = domain->name;
	domain->sysfs_group.attrs = octtx_def_attrs;
	ret = sysfs_create_group(&octtx_device->kobj, &domain->sysfs_group);
	if (ret < 0) {
		dev_err(octtx_device, " create_domain sysfs failed\n");
		goto error;
	}

	if (fpa_count > 0) {
		domain->fpa_vf_count = fpa_count;
		domain->aura_set = fpapf->create_domain(node, domain_id,
						domain->fpa_vf_count,
						&octtx_device->kobj,
						domain->name);
		if (!domain->aura_set) {
			dev_err(octtx_device, "Failed to create FPA domain\n");
			ret = -ENODEV;
			goto error;
		}
	}

	domain->ssow_vf_count = ssow_count;
	ret = ssowpf->create_domain(node, domain_id, domain->ssow_vf_count,
				&octtx_master_com, domain,
				&octtx_device->kobj, domain->name);
	if (ret) {
		dev_err(octtx_device, "Failed to create SSOW domain\n");
		goto error;
	}

	domain->sso_vf_count = sso_count;
	domain->grp_mask = ssopf->create_domain(node, domain_id,
			domain->sso_vf_count,
			&octtx_master_com, domain,
			&octtx_device->kobj, domain->name);
	if (!domain->grp_mask) {
		dev_err(octtx_device, "Failed to create SSO domain\n");
		goto error;
	}

	ret = ssowpf->get_ram_mbox_addr(node, domain_id, &ssow_ram_mbox_addr);
	if (ret) {
		dev_err(octtx_device, "Failed to get_ssow_ram_mbox_addr\n");
		goto error;
	}

	ret = ssopf->set_mbox_ram(node, domain_id,
				  ssow_ram_mbox_addr, SSOW_RAM_MBOX_SIZE);
	if (ret) {
		dev_err(octtx_device, "Failed to set_ram_addr\n");
		goto error;
	}

	domain->dom_attr.show = octtx_domain_id_show;
	domain->dom_attr.attr.name = "domain_id";
	domain->dom_attr.attr.mode = S_IRUGO;
	sysfs_attr_init(&domain->dom_attr.attr);
	ret = sysfs_add_file_to_group(&octtx_device->kobj,
				      &domain->dom_attr.attr, domain->name);
	if (ret < 0) {
		dev_err(octtx_device, " create_domain sysfs failed\n");
		goto error;
	}
	spin_lock(&octeontx_domains_lock);
	INIT_LIST_HEAD(&domain->list);
	list_add(&domain->list, &octeontx_domains);
	spin_unlock(&octeontx_domains_lock);
	return 0;
error:
	octeontx_remove_domain(node, domain_id);
	return ret;
}

static int octeontx_reset_domain(void *master_data)
{
	struct octtx_domain *domain = master_data;
	void *ssow_ram_mbox_addr = NULL;
	int node = domain->node;
	int ret;

	ret = ssopf->reset_domain(node, domain->domain_id);
	if (ret) {
		dev_err(octtx_device,
			"Failed to reset SSO of domain %d on node %d.\n",
		       domain->domain_id, node);
		return ret;
	}
	ret = ssowpf->reset_domain(node, domain->domain_id, domain->grp_mask);
	if (ret) {
		dev_err(octtx_device,
			"Failed to reset SSOW of domain %d on node %d.\n",
		       domain->domain_id, node);
		return ret;
	}
	/* FPA reset should be the last one to call*/
	ret = fpapf->reset_domain(node, domain->domain_id);
	if (ret) {
		dev_err(octtx_device,
			"Failed to reset FPA of domain %d on node %d.\n",
		       domain->domain_id, node);
		return ret;
	}
	/* Reset mailbox */
	ret = ssowpf->get_ram_mbox_addr(node, domain->domain_id,
					&ssow_ram_mbox_addr);
	if (ret) {
		dev_err(octtx_device,
			"Failed to get_ssow_ram_mbox_addr for node (%d): "
		       "domain (%d)\n", node, domain->domain_id);
		return ret;
	}
	ret = ssopf->set_mbox_ram(node, domain->domain_id,
				  ssow_ram_mbox_addr, SSOW_RAM_MBOX_SIZE);
	if (ret) {
		dev_err(octtx_device,
			"Failed to set_ram_addr for node (%d): domain (%d)\n",
		       node, domain->domain_id);
		return ret;
	}

	return 0;
}

void octtx_reset_domain(struct work_struct *work)
{
	struct octtx_domain *domain;
	int i, master_sso;
	extern atomic_t octtx_sso_reset[];
	u64 val;

	spin_lock(&octeontx_domains_lock);
	list_for_each_entry(domain, &octeontx_domains, list) {
		/* find first SSO from domain */
		master_sso = __ffs(domain->grp_mask);
		for_each_set_bit(i, (unsigned long *)&domain->grp_mask,
				sizeof(domain->aura_set) * 8) {
			val = atomic_read(&octtx_sso_reset[i]);
			if ((master_sso == i) && val) {
				spin_unlock(&octeontx_domains_lock);
				octeontx_reset_domain(domain);
				spin_lock(&octeontx_domains_lock);
			}
			atomic_set(&octtx_sso_reset[i], 0);
			/*makesure the otherend receives it*/
			mb();
		}
	}
	spin_unlock(&octeontx_domains_lock);
	queue_delayed_work(reset_domain, &dwork_reset, 10);
}

static int octtx_dev_open(struct inode *inode, struct file *fp)
{
	/* Nothing to do */
	return 0;
}

static int octtx_dev_release(struct inode *inode, struct file *fp)
{
	return 0;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = octtx_dev_open,
	.release = octtx_dev_release
};

static int __init octeontx_init_module(void)
{
	int ret;

	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

	fpapf = try_then_request_module(symbol_get(fpapf_com), "fpapf");
	if (!fpapf)
		return -ENODEV;
	ssopf = try_then_request_module(symbol_get(ssopf_com), "ssopf");
	if (!ssopf) {
		symbol_put(fpapf_com);
		return -ENODEV;
	}
	ssowpf = try_then_request_module(symbol_get(ssowpf_com), "ssowpf");
	if (!ssowpf) {
		symbol_put(ssopf_com);
		symbol_put(fpapf_com);
		return -ENODEV;
	}

	/* Register a physical link status poll fn() */
	check_link = alloc_workqueue("octeontx_check_link_status",
				     WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!check_link) {
		symbol_put(ssopf_com);
		symbol_put(ssowpf_com);
		symbol_put(fpapf_com);
		return -ENOMEM;
	}

	/* Register a physical link status poll fn() */
	reset_domain = alloc_workqueue("octeontx_reset_domain",
				     WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!reset_domain) {
		symbol_put(ssopf_com);
		symbol_put(ssowpf_com);
		symbol_put(fpapf_com);
		return -ENOMEM;
	}
	INIT_DELAYED_WORK(&dwork_reset, octtx_reset_domain);
	queue_delayed_work(reset_domain, &dwork_reset, 0);

	/* create a char device */
	ret = alloc_chrdev_region(&octtx_dev, 1, 1, DEVICE_NAME);
	if (ret != 0) {
		symbol_put(ssopf_com);
		symbol_put(ssowpf_com);
		symbol_put(fpapf_com);
		return -ENODEV;
	}
	octtx_cdev = cdev_alloc();
	if (!octtx_cdev) {
		symbol_put(ssopf_com);
		symbol_put(ssowpf_com);
		symbol_put(fpapf_com);
		return -ENODEV;
	}
	cdev_init(octtx_cdev, &fops);
	ret = cdev_add(octtx_cdev, octtx_dev, 1);
	if (ret < 0) {
		cdev_del(octtx_cdev);
		symbol_put(ssopf_com);
		symbol_put(ssowpf_com);
		symbol_put(fpapf_com);
		return -ENODEV;
	}

	/* create new class for sysfs*/
	octtx_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(octtx_class)) {
		cdev_del(octtx_cdev);
		symbol_put(ssopf_com);
		symbol_put(ssowpf_com);
		symbol_put(fpapf_com);
		return -ENODEV;
	}

	octtx_device = device_create(octtx_class, NULL, octtx_dev, NULL,
					DEVICE_NAME);
	if (IS_ERR(octtx_device)) {
		class_unregister(octtx_class);
		class_destroy(octtx_class);
		cdev_del(octtx_cdev);
		symbol_put(ssopf_com);
		symbol_put(ssowpf_com);
		symbol_put(fpapf_com);
		return -ENODEV;
	}

	octtx_sysfs_init(octtx_device);
	/* Done */
	return 0;
}

static void __exit octeontx_cleanup_module(void)
{
	octtx_sysfs_remove(octtx_device);
	device_destroy(octtx_class, octtx_dev);
	class_unregister(octtx_class);
	class_destroy(octtx_class);
	cdev_del(octtx_cdev);
	symbol_put(ssopf_com);
	symbol_put(ssowpf_com);
	symbol_put(fpapf_com);
}

module_init(octeontx_init_module);
module_exit(octeontx_cleanup_module);
