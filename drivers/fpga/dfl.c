// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for FPGA Device Feature List (DFL) Support
 *
 * Copyright (C) 2017-2018 Intel Corporation, Inc.
 *
 * Authors:
 *   Kang Luwei <luwei.kang@intel.com>
 *   Zhang Yi <yi.z.zhang@intel.com>
 *   Wu Hao <hao.wu@intel.com>
 *   Xiao Guangrong <guangrong.xiao@linux.intel.com>
 */
#include <linux/dfl.h>
#include <linux/fpga-dfl.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/uaccess.h>

#include "dfl.h"

static DEFINE_MUTEX(dfl_id_mutex);

/*
 * when adding a new feature dev support in DFL framework, it's required to
 * add a new item in enum dfl_id_type and provide related information in below
 * dfl_devs table which is indexed by dfl_id_type, e.g. name string used for
 * platform device creation (define name strings in dfl.h, as they could be
 * reused by platform device drivers).
 *
 * if the new feature dev needs chardev support, then it's required to add
 * a new item in dfl_chardevs table and configure dfl_devs[i].devt_type as
 * index to dfl_chardevs table. If no chardev support just set devt_type
 * as one invalid index (DFL_FPGA_DEVT_MAX).
 */
enum dfl_fpga_devt_type {
	DFL_FPGA_DEVT_FME,
	DFL_FPGA_DEVT_PORT,
	DFL_FPGA_DEVT_MAX,
};

static struct lock_class_key dfl_pdata_keys[DFL_ID_MAX];

static const char *dfl_pdata_key_strings[DFL_ID_MAX] = {
	"dfl-fme-pdata",
	"dfl-port-pdata",
};

/**
 * struct dfl_dev_info - dfl feature device information.
 * @name: name string of the feature platform device.
 * @dfh_id: id value in Device Feature Header (DFH) register by DFL spec.
 * @id: idr id of the feature dev.
 * @devt_type: index to dfl_chrdevs[].
 */
struct dfl_dev_info {
	const char *name;
	u16 dfh_id;
	struct idr id;
	enum dfl_fpga_devt_type devt_type;
};

/* it is indexed by dfl_id_type */
static struct dfl_dev_info dfl_devs[] = {
	{.name = DFL_FPGA_FEATURE_DEV_FME, .dfh_id = DFH_ID_FIU_FME,
	 .devt_type = DFL_FPGA_DEVT_FME},
	{.name = DFL_FPGA_FEATURE_DEV_PORT, .dfh_id = DFH_ID_FIU_PORT,
	 .devt_type = DFL_FPGA_DEVT_PORT},
};

/**
 * struct dfl_chardev_info - chardev information of dfl feature device
 * @name: nmae string of the char device.
 * @devt: devt of the char device.
 */
struct dfl_chardev_info {
	const char *name;
	dev_t devt;
};

/* indexed by enum dfl_fpga_devt_type */
static struct dfl_chardev_info dfl_chrdevs[] = {
	{.name = DFL_FPGA_FEATURE_DEV_FME},
	{.name = DFL_FPGA_FEATURE_DEV_PORT},
};

static void dfl_ids_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dfl_devs); i++)
		idr_init(&dfl_devs[i].id);
}

static void dfl_ids_destroy(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dfl_devs); i++)
		idr_destroy(&dfl_devs[i].id);
}

static int dfl_id_alloc(enum dfl_id_type type, struct device *dev)
{
	int id;

	WARN_ON(type >= DFL_ID_MAX);
	mutex_lock(&dfl_id_mutex);
	id = idr_alloc(&dfl_devs[type].id, dev, 0, 0, GFP_KERNEL);
	mutex_unlock(&dfl_id_mutex);

	return id;
}

static void dfl_id_free(enum dfl_id_type type, int id)
{
	WARN_ON(type >= DFL_ID_MAX);
	mutex_lock(&dfl_id_mutex);
	idr_remove(&dfl_devs[type].id, id);
	mutex_unlock(&dfl_id_mutex);
}

static enum dfl_id_type dfh_id_to_type(u16 id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dfl_devs); i++)
		if (dfl_devs[i].dfh_id == id)
			return i;

	return DFL_ID_MAX;
}

/*
 * introduce a global port_ops list, it allows port drivers to register ops
 * in such list, then other feature devices (e.g. FME), could use the port
 * functions even related port platform device is hidden. Below is one example,
 * in virtualization case of PCIe-based FPGA DFL device, when SRIOV is
 * enabled, port (and it's AFU) is turned into VF and port platform device
 * is hidden from system but it's still required to access port to finish FPGA
 * reconfiguration function in FME.
 */

static DEFINE_MUTEX(dfl_port_ops_mutex);
static LIST_HEAD(dfl_port_ops_list);

/**
 * dfl_fpga_port_ops_get - get matched port ops from the global list
 * @fdata: feature dev data to match with associated port ops.
 * Return: matched port ops on success, NULL otherwise.
 *
 * Please note that must dfl_fpga_port_ops_put after use the port_ops.
 */
struct dfl_fpga_port_ops *dfl_fpga_port_ops_get(struct dfl_feature_dev_data *fdata)
{
	struct dfl_fpga_port_ops *ops = NULL;

	mutex_lock(&dfl_port_ops_mutex);
	if (list_empty(&dfl_port_ops_list))
		goto done;

	list_for_each_entry(ops, &dfl_port_ops_list, node) {
		/* match port_ops using the name of platform device */
		if (!strcmp(fdata->pdev_name, ops->name)) {
			if (!try_module_get(ops->owner))
				ops = NULL;
			goto done;
		}
	}

	ops = NULL;
done:
	mutex_unlock(&dfl_port_ops_mutex);
	return ops;
}
EXPORT_SYMBOL_GPL(dfl_fpga_port_ops_get);

/**
 * dfl_fpga_port_ops_put - put port ops
 * @ops: port ops.
 */
void dfl_fpga_port_ops_put(struct dfl_fpga_port_ops *ops)
{
	if (ops && ops->owner)
		module_put(ops->owner);
}
EXPORT_SYMBOL_GPL(dfl_fpga_port_ops_put);

/**
 * dfl_fpga_port_ops_add - add port_ops to global list
 * @ops: port ops to add.
 */
void dfl_fpga_port_ops_add(struct dfl_fpga_port_ops *ops)
{
	mutex_lock(&dfl_port_ops_mutex);
	list_add_tail(&ops->node, &dfl_port_ops_list);
	mutex_unlock(&dfl_port_ops_mutex);
}
EXPORT_SYMBOL_GPL(dfl_fpga_port_ops_add);

/**
 * dfl_fpga_port_ops_del - remove port_ops from global list
 * @ops: port ops to del.
 */
void dfl_fpga_port_ops_del(struct dfl_fpga_port_ops *ops)
{
	mutex_lock(&dfl_port_ops_mutex);
	list_del(&ops->node);
	mutex_unlock(&dfl_port_ops_mutex);
}
EXPORT_SYMBOL_GPL(dfl_fpga_port_ops_del);

/**
 * dfl_fpga_check_port_id - check the port id
 * @fdata: port feature dev data.
 * @pport_id: port id to compare.
 *
 * Return: 1 if port device matches with given port id, otherwise 0.
 */
int dfl_fpga_check_port_id(struct dfl_feature_dev_data *fdata, void *pport_id)
{
	struct dfl_fpga_port_ops *port_ops;

	if (fdata->id != FEATURE_DEV_ID_UNUSED)
		return fdata->id == *(int *)pport_id;

	port_ops = dfl_fpga_port_ops_get(fdata);
	if (!port_ops || !port_ops->get_id)
		return 0;

	fdata->id = port_ops->get_id(fdata);
	dfl_fpga_port_ops_put(port_ops);

	return fdata->id == *(int *)pport_id;
}
EXPORT_SYMBOL_GPL(dfl_fpga_check_port_id);

static DEFINE_IDA(dfl_device_ida);

static const struct dfl_device_id *
dfl_match_one_device(const struct dfl_device_id *id, struct dfl_device *ddev)
{
	if (id->type == ddev->type && id->feature_id == ddev->feature_id)
		return id;

	return NULL;
}

static int dfl_bus_match(struct device *dev, const struct device_driver *drv)
{
	struct dfl_device *ddev = to_dfl_dev(dev);
	const struct dfl_driver *ddrv = to_dfl_drv(drv);
	const struct dfl_device_id *id_entry;

	id_entry = ddrv->id_table;
	if (id_entry) {
		while (id_entry->feature_id) {
			if (dfl_match_one_device(id_entry, ddev)) {
				ddev->id_entry = id_entry;
				return 1;
			}
			id_entry++;
		}
	}

	return 0;
}

static int dfl_bus_probe(struct device *dev)
{
	struct dfl_driver *ddrv = to_dfl_drv(dev->driver);
	struct dfl_device *ddev = to_dfl_dev(dev);

	return ddrv->probe(ddev);
}

static void dfl_bus_remove(struct device *dev)
{
	struct dfl_driver *ddrv = to_dfl_drv(dev->driver);
	struct dfl_device *ddev = to_dfl_dev(dev);

	if (ddrv->remove)
		ddrv->remove(ddev);
}

static int dfl_bus_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
	const struct dfl_device *ddev = to_dfl_dev(dev);

	return add_uevent_var(env, "MODALIAS=dfl:t%04Xf%04X",
			      ddev->type, ddev->feature_id);
}

static ssize_t
type_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct dfl_device *ddev = to_dfl_dev(dev);

	return sprintf(buf, "0x%x\n", ddev->type);
}
static DEVICE_ATTR_RO(type);

static ssize_t
feature_id_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct dfl_device *ddev = to_dfl_dev(dev);

	return sprintf(buf, "0x%x\n", ddev->feature_id);
}
static DEVICE_ATTR_RO(feature_id);

static struct attribute *dfl_dev_attrs[] = {
	&dev_attr_type.attr,
	&dev_attr_feature_id.attr,
	NULL,
};
ATTRIBUTE_GROUPS(dfl_dev);

static const struct bus_type dfl_bus_type = {
	.name		= "dfl",
	.match		= dfl_bus_match,
	.probe		= dfl_bus_probe,
	.remove		= dfl_bus_remove,
	.uevent		= dfl_bus_uevent,
	.dev_groups	= dfl_dev_groups,
};

static void release_dfl_dev(struct device *dev)
{
	struct dfl_device *ddev = to_dfl_dev(dev);

	if (ddev->mmio_res.parent)
		release_resource(&ddev->mmio_res);

	kfree(ddev->params);

	ida_free(&dfl_device_ida, ddev->id);
	kfree(ddev->irqs);
	kfree(ddev);
}

static struct dfl_device *
dfl_dev_add(struct dfl_feature_dev_data *fdata,
	    struct dfl_feature *feature)
{
	struct platform_device *pdev = fdata->dev;
	struct resource *parent_res;
	struct dfl_device *ddev;
	int id, i, ret;

	ddev = kzalloc(sizeof(*ddev), GFP_KERNEL);
	if (!ddev)
		return ERR_PTR(-ENOMEM);

	id = ida_alloc(&dfl_device_ida, GFP_KERNEL);
	if (id < 0) {
		dev_err(&pdev->dev, "unable to get id\n");
		kfree(ddev);
		return ERR_PTR(id);
	}

	/* freeing resources by put_device() after device_initialize() */
	device_initialize(&ddev->dev);
	ddev->dev.parent = &pdev->dev;
	ddev->dev.bus = &dfl_bus_type;
	ddev->dev.release = release_dfl_dev;
	ddev->id = id;
	ret = dev_set_name(&ddev->dev, "dfl_dev.%d", id);
	if (ret)
		goto put_dev;

	ddev->type = fdata->type;
	ddev->feature_id = feature->id;
	ddev->revision = feature->revision;
	ddev->dfh_version = feature->dfh_version;
	ddev->cdev = fdata->dfl_cdev;
	if (feature->param_size) {
		ddev->params = kmemdup(feature->params, feature->param_size, GFP_KERNEL);
		if (!ddev->params) {
			ret = -ENOMEM;
			goto put_dev;
		}
		ddev->param_size = feature->param_size;
	}

	/* add mmio resource */
	parent_res = &pdev->resource[feature->resource_index];
	ddev->mmio_res.flags = IORESOURCE_MEM;
	ddev->mmio_res.start = parent_res->start;
	ddev->mmio_res.end = parent_res->end;
	ddev->mmio_res.name = dev_name(&ddev->dev);
	ret = insert_resource(parent_res, &ddev->mmio_res);
	if (ret) {
		dev_err(&pdev->dev, "%s failed to claim resource: %pR\n",
			dev_name(&ddev->dev), &ddev->mmio_res);
		goto put_dev;
	}

	/* then add irq resource */
	if (feature->nr_irqs) {
		ddev->irqs = kcalloc(feature->nr_irqs,
				     sizeof(*ddev->irqs), GFP_KERNEL);
		if (!ddev->irqs) {
			ret = -ENOMEM;
			goto put_dev;
		}

		for (i = 0; i < feature->nr_irqs; i++)
			ddev->irqs[i] = feature->irq_ctx[i].irq;

		ddev->num_irqs = feature->nr_irqs;
	}

	ret = device_add(&ddev->dev);
	if (ret)
		goto put_dev;

	dev_dbg(&pdev->dev, "add dfl_dev: %s\n", dev_name(&ddev->dev));
	return ddev;

put_dev:
	/* calls release_dfl_dev() which does the clean up  */
	put_device(&ddev->dev);
	return ERR_PTR(ret);
}

static void dfl_devs_remove(struct dfl_feature_dev_data *fdata)
{
	struct dfl_feature *feature;

	dfl_fpga_dev_for_each_feature(fdata, feature) {
		if (feature->ddev) {
			device_unregister(&feature->ddev->dev);
			feature->ddev = NULL;
		}
	}
}

static int dfl_devs_add(struct dfl_feature_dev_data *fdata)
{
	struct dfl_feature *feature;
	struct dfl_device *ddev;
	int ret;

	dfl_fpga_dev_for_each_feature(fdata, feature) {
		if (feature->ioaddr)
			continue;

		if (feature->ddev) {
			ret = -EEXIST;
			goto err;
		}

		ddev = dfl_dev_add(fdata, feature);
		if (IS_ERR(ddev)) {
			ret = PTR_ERR(ddev);
			goto err;
		}

		feature->ddev = ddev;
	}

	return 0;

err:
	dfl_devs_remove(fdata);
	return ret;
}

int __dfl_driver_register(struct dfl_driver *dfl_drv, struct module *owner)
{
	if (!dfl_drv || !dfl_drv->probe || !dfl_drv->id_table)
		return -EINVAL;

	dfl_drv->drv.owner = owner;
	dfl_drv->drv.bus = &dfl_bus_type;

	return driver_register(&dfl_drv->drv);
}
EXPORT_SYMBOL(__dfl_driver_register);

void dfl_driver_unregister(struct dfl_driver *dfl_drv)
{
	driver_unregister(&dfl_drv->drv);
}
EXPORT_SYMBOL(dfl_driver_unregister);

#define is_header_feature(feature) ((feature)->id == FEATURE_ID_FIU_HEADER)

/**
 * dfl_fpga_dev_feature_uinit - uinit for sub features of dfl feature device
 * @pdev: feature device.
 */
void dfl_fpga_dev_feature_uinit(struct platform_device *pdev)
{
	struct dfl_feature_dev_data *fdata = to_dfl_feature_dev_data(&pdev->dev);
	struct dfl_feature *feature;

	dfl_devs_remove(fdata);

	dfl_fpga_dev_for_each_feature(fdata, feature) {
		if (feature->ops) {
			if (feature->ops->uinit)
				feature->ops->uinit(pdev, feature);
			feature->ops = NULL;
		}
	}
}
EXPORT_SYMBOL_GPL(dfl_fpga_dev_feature_uinit);

static int dfl_feature_instance_init(struct platform_device *pdev,
				     struct dfl_feature *feature,
				     struct dfl_feature_driver *drv)
{
	void __iomem *base;
	int ret = 0;

	if (!is_header_feature(feature)) {
		base = devm_platform_ioremap_resource(pdev,
						      feature->resource_index);
		if (IS_ERR(base)) {
			dev_err(&pdev->dev,
				"ioremap failed for feature 0x%x!\n",
				feature->id);
			return PTR_ERR(base);
		}

		feature->ioaddr = base;
	}

	if (drv->ops->init) {
		ret = drv->ops->init(pdev, feature);
		if (ret)
			return ret;
	}

	feature->ops = drv->ops;

	return ret;
}

static bool dfl_feature_drv_match(struct dfl_feature *feature,
				  struct dfl_feature_driver *driver)
{
	const struct dfl_feature_id *ids = driver->id_table;

	if (ids) {
		while (ids->id) {
			if (ids->id == feature->id)
				return true;
			ids++;
		}
	}
	return false;
}

/**
 * dfl_fpga_dev_feature_init - init for sub features of dfl feature device
 * @pdev: feature device.
 * @feature_drvs: drvs for sub features.
 *
 * This function will match sub features with given feature drvs list and
 * use matched drv to init related sub feature.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int dfl_fpga_dev_feature_init(struct platform_device *pdev,
			      struct dfl_feature_driver *feature_drvs)
{
	struct dfl_feature_dev_data *fdata = to_dfl_feature_dev_data(&pdev->dev);
	struct dfl_feature_driver *drv = feature_drvs;
	struct dfl_feature *feature;
	int ret;

	while (drv->ops) {
		dfl_fpga_dev_for_each_feature(fdata, feature) {
			if (dfl_feature_drv_match(feature, drv)) {
				ret = dfl_feature_instance_init(pdev, feature, drv);
				if (ret)
					goto exit;
			}
		}
		drv++;
	}

	ret = dfl_devs_add(fdata);
	if (ret)
		goto exit;

	return 0;
exit:
	dfl_fpga_dev_feature_uinit(pdev);
	return ret;
}
EXPORT_SYMBOL_GPL(dfl_fpga_dev_feature_init);

static void dfl_chardev_uinit(void)
{
	int i;

	for (i = 0; i < DFL_FPGA_DEVT_MAX; i++)
		if (MAJOR(dfl_chrdevs[i].devt)) {
			unregister_chrdev_region(dfl_chrdevs[i].devt,
						 MINORMASK + 1);
			dfl_chrdevs[i].devt = MKDEV(0, 0);
		}
}

static int dfl_chardev_init(void)
{
	int i, ret;

	for (i = 0; i < DFL_FPGA_DEVT_MAX; i++) {
		ret = alloc_chrdev_region(&dfl_chrdevs[i].devt, 0,
					  MINORMASK + 1, dfl_chrdevs[i].name);
		if (ret)
			goto exit;
	}

	return 0;

exit:
	dfl_chardev_uinit();
	return ret;
}

static dev_t dfl_get_devt(enum dfl_fpga_devt_type type, int id)
{
	if (type >= DFL_FPGA_DEVT_MAX)
		return 0;

	return MKDEV(MAJOR(dfl_chrdevs[type].devt), id);
}

/**
 * dfl_fpga_dev_ops_register - register cdev ops for feature dev
 *
 * @pdev: feature dev.
 * @fops: file operations for feature dev's cdev.
 * @owner: owning module/driver.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int dfl_fpga_dev_ops_register(struct platform_device *pdev,
			      const struct file_operations *fops,
			      struct module *owner)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(&pdev->dev);

	cdev_init(&pdata->cdev, fops);
	pdata->cdev.owner = owner;

	/*
	 * set parent to the feature device so that its refcount is
	 * decreased after the last refcount of cdev is gone, that
	 * makes sure the feature device is valid during device
	 * file's life-cycle.
	 */
	pdata->cdev.kobj.parent = &pdev->dev.kobj;

	return cdev_add(&pdata->cdev, pdev->dev.devt, 1);
}
EXPORT_SYMBOL_GPL(dfl_fpga_dev_ops_register);

/**
 * dfl_fpga_dev_ops_unregister - unregister cdev ops for feature dev
 * @pdev: feature dev.
 */
void dfl_fpga_dev_ops_unregister(struct platform_device *pdev)
{
	struct dfl_feature_platform_data *pdata = dev_get_platdata(&pdev->dev);

	cdev_del(&pdata->cdev);
}
EXPORT_SYMBOL_GPL(dfl_fpga_dev_ops_unregister);

/**
 * struct build_feature_devs_info - info collected during feature dev build.
 *
 * @dev: device to enumerate.
 * @cdev: the container device for all feature devices.
 * @nr_irqs: number of irqs for all feature devices.
 * @irq_table: Linux IRQ numbers for all irqs, indexed by local irq index of
 *	       this device.
 * @type: the current FIU type.
 * @ioaddr: header register region address of current FIU in enumeration.
 * @start: register resource start of current FIU.
 * @len: max register resource length of current FIU.
 * @sub_features: a sub features linked list for feature device in enumeration.
 * @feature_num: number of sub features for feature device in enumeration.
 */
struct build_feature_devs_info {
	struct device *dev;
	struct dfl_fpga_cdev *cdev;
	unsigned int nr_irqs;
	int *irq_table;

	enum dfl_id_type type;
	void __iomem *ioaddr;
	resource_size_t start;
	resource_size_t len;
	struct list_head sub_features;
	int feature_num;
};

/**
 * struct dfl_feature_info - sub feature info collected during feature dev build
 *
 * @fid: id of this sub feature.
 * @revision: revision of this sub feature
 * @dfh_version: version of Device Feature Header (DFH)
 * @mmio_res: mmio resource of this sub feature.
 * @ioaddr: mapped base address of mmio resource.
 * @node: node in sub_features linked list.
 * @irq_base: start of irq index in this sub feature.
 * @nr_irqs: number of irqs of this sub feature.
 * @param_size: size DFH parameters.
 * @params: DFH parameter data.
 */
struct dfl_feature_info {
	u16 fid;
	u8 revision;
	u8 dfh_version;
	struct resource mmio_res;
	void __iomem *ioaddr;
	struct list_head node;
	unsigned int irq_base;
	unsigned int nr_irqs;
	unsigned int param_size;
	u64 params[];
};

static void dfl_fpga_cdev_add_port_data(struct dfl_fpga_cdev *cdev,
					struct dfl_feature_dev_data *fdata)
{
	mutex_lock(&cdev->lock);
	list_add(&fdata->node, &cdev->port_dev_list);
	mutex_unlock(&cdev->lock);
}

static void dfl_id_free_action(void *arg)
{
	struct dfl_feature_dev_data *fdata = arg;

	dfl_id_free(fdata->type, fdata->pdev_id);
}

static struct dfl_feature_dev_data *
binfo_create_feature_dev_data(struct build_feature_devs_info *binfo)
{
	enum dfl_id_type type = binfo->type;
	struct dfl_feature_info *finfo, *p;
	struct dfl_feature_dev_data *fdata;
	int ret, index = 0, res_idx = 0;

	if (WARN_ON_ONCE(type >= DFL_ID_MAX))
		return ERR_PTR(-EINVAL);

	fdata = devm_kzalloc(binfo->dev, sizeof(*fdata), GFP_KERNEL);
	if (!fdata)
		return ERR_PTR(-ENOMEM);

	fdata->features = devm_kcalloc(binfo->dev, binfo->feature_num,
				       sizeof(*fdata->features), GFP_KERNEL);
	if (!fdata->features)
		return ERR_PTR(-ENOMEM);

	fdata->resources = devm_kcalloc(binfo->dev, binfo->feature_num,
					sizeof(*fdata->resources), GFP_KERNEL);
	if (!fdata->resources)
		return ERR_PTR(-ENOMEM);

	fdata->type = type;

	fdata->pdev_id = dfl_id_alloc(type, binfo->dev);
	if (fdata->pdev_id < 0)
		return ERR_PTR(fdata->pdev_id);

	ret = devm_add_action_or_reset(binfo->dev, dfl_id_free_action, fdata);
	if (ret)
		return ERR_PTR(ret);

	fdata->pdev_name = dfl_devs[type].name;
	fdata->num = binfo->feature_num;
	fdata->dfl_cdev = binfo->cdev;
	fdata->id = FEATURE_DEV_ID_UNUSED;
	mutex_init(&fdata->lock);
	lockdep_set_class_and_name(&fdata->lock, &dfl_pdata_keys[type],
				   dfl_pdata_key_strings[type]);

	/*
	 * the count should be initialized to 0 to make sure
	 *__fpga_port_enable() following __fpga_port_disable()
	 * works properly for port device.
	 * and it should always be 0 for fme device.
	 */
	WARN_ON(fdata->disable_count);

	/* fill features and resource information for feature dev */
	list_for_each_entry_safe(finfo, p, &binfo->sub_features, node) {
		struct dfl_feature *feature = &fdata->features[index++];
		struct dfl_feature_irq_ctx *ctx;
		unsigned int i;

		/* save resource information for each feature */
		feature->id = finfo->fid;
		feature->revision = finfo->revision;
		feature->dfh_version = finfo->dfh_version;

		if (finfo->param_size) {
			feature->params = devm_kmemdup(binfo->dev,
						       finfo->params, finfo->param_size,
						       GFP_KERNEL);
			if (!feature->params)
				return ERR_PTR(-ENOMEM);

			feature->param_size = finfo->param_size;
		}
		/*
		 * the FIU header feature has some fundamental functions (sriov
		 * set, port enable/disable) needed for the dfl bus device and
		 * other sub features. So its mmio resource should be mapped by
		 * DFL bus device. And we should not assign it to feature
		 * devices (dfl-fme/afu) again.
		 */
		if (is_header_feature(feature)) {
			feature->resource_index = -1;
			feature->ioaddr =
				devm_ioremap_resource(binfo->dev,
						      &finfo->mmio_res);
			if (IS_ERR(feature->ioaddr))
				return ERR_CAST(feature->ioaddr);
		} else {
			feature->resource_index = res_idx;
			fdata->resources[res_idx++] = finfo->mmio_res;
		}

		if (finfo->nr_irqs) {
			ctx = devm_kcalloc(binfo->dev, finfo->nr_irqs,
					   sizeof(*ctx), GFP_KERNEL);
			if (!ctx)
				return ERR_PTR(-ENOMEM);

			for (i = 0; i < finfo->nr_irqs; i++)
				ctx[i].irq =
					binfo->irq_table[finfo->irq_base + i];

			feature->irq_ctx = ctx;
			feature->nr_irqs = finfo->nr_irqs;
		}

		list_del(&finfo->node);
		kfree(finfo);
	}

	fdata->resource_num = res_idx;

	return fdata;
}

/*
 * register current feature device, it is called when we need to switch to
 * another feature parsing or we have parsed all features on given device
 * feature list.
 */
static int feature_dev_register(struct dfl_feature_dev_data *fdata)
{
	struct dfl_feature_platform_data pdata = {};
	struct platform_device *fdev;
	struct dfl_feature *feature;
	int ret;

	fdev = platform_device_alloc(fdata->pdev_name, fdata->pdev_id);
	if (!fdev)
		return -ENOMEM;

	fdata->dev = fdev;

	fdev->dev.parent = &fdata->dfl_cdev->region->dev;
	fdev->dev.devt = dfl_get_devt(dfl_devs[fdata->type].devt_type, fdev->id);

	dfl_fpga_dev_for_each_feature(fdata, feature)
		feature->dev = fdev;

	ret = platform_device_add_resources(fdev, fdata->resources,
					    fdata->resource_num);
	if (ret)
		goto err_put_dev;

	pdata.fdata = fdata;
	ret = platform_device_add_data(fdev, &pdata, sizeof(pdata));
	if (ret)
		goto err_put_dev;

	ret = platform_device_add(fdev);
	if (ret)
		goto err_put_dev;

	return 0;

err_put_dev:
	platform_device_put(fdev);

	fdata->dev = NULL;

	dfl_fpga_dev_for_each_feature(fdata, feature)
		feature->dev = NULL;

	return ret;
}

static void feature_dev_unregister(struct dfl_feature_dev_data *fdata)
{
	struct dfl_feature *feature;

	platform_device_unregister(fdata->dev);

	fdata->dev = NULL;

	dfl_fpga_dev_for_each_feature(fdata, feature)
		feature->dev = NULL;
}

static int build_info_commit_dev(struct build_feature_devs_info *binfo)
{
	struct dfl_feature_dev_data *fdata;
	int ret;

	fdata = binfo_create_feature_dev_data(binfo);
	if (IS_ERR(fdata))
		return PTR_ERR(fdata);

	ret = feature_dev_register(fdata);
	if (ret)
		return ret;

	if (binfo->type == PORT_ID)
		dfl_fpga_cdev_add_port_data(binfo->cdev, fdata);
	else
		binfo->cdev->fme_dev = get_device(&fdata->dev->dev);

	/* reset the binfo for next FIU */
	binfo->type = DFL_ID_MAX;

	return 0;
}

static void build_info_free(struct build_feature_devs_info *binfo)
{
	struct dfl_feature_info *finfo, *p;

	list_for_each_entry_safe(finfo, p, &binfo->sub_features, node) {
		list_del(&finfo->node);
		kfree(finfo);
	}

	devm_kfree(binfo->dev, binfo);
}

static inline u32 feature_size(u64 value)
{
	u32 ofst = FIELD_GET(DFH_NEXT_HDR_OFST, value);
	/* workaround for private features with invalid size, use 4K instead */
	return ofst ? ofst : 4096;
}

static u16 feature_id(u64 value)
{
	u16 id = FIELD_GET(DFH_ID, value);
	u8 type = FIELD_GET(DFH_TYPE, value);

	if (type == DFH_TYPE_FIU)
		return FEATURE_ID_FIU_HEADER;
	else if (type == DFH_TYPE_PRIVATE)
		return id;
	else if (type == DFH_TYPE_AFU)
		return FEATURE_ID_AFU;

	WARN_ON(1);
	return 0;
}

static u64 *find_param(u64 *params, resource_size_t max, int param_id)
{
	u64 *end = params + max / sizeof(u64);
	u64 v, next;

	while (params < end) {
		v = *params;
		if (param_id == FIELD_GET(DFHv1_PARAM_HDR_ID, v))
			return params;

		if (FIELD_GET(DFHv1_PARAM_HDR_NEXT_EOP, v))
			break;

		next = FIELD_GET(DFHv1_PARAM_HDR_NEXT_OFFSET, v);
		params += next;
	}

	return NULL;
}

/**
 * dfh_find_param() - find parameter block for the given parameter id
 * @dfl_dev: dfl device
 * @param_id: id of dfl parameter
 * @psize: destination to store size of parameter data in bytes
 *
 * Return: pointer to start of parameter data, PTR_ERR otherwise.
 */
void *dfh_find_param(struct dfl_device *dfl_dev, int param_id, size_t *psize)
{
	u64 *phdr = find_param(dfl_dev->params, dfl_dev->param_size, param_id);

	if (!phdr)
		return ERR_PTR(-ENOENT);

	if (psize)
		*psize = (FIELD_GET(DFHv1_PARAM_HDR_NEXT_OFFSET, *phdr) - 1) * sizeof(u64);

	return phdr + 1;
}
EXPORT_SYMBOL_GPL(dfh_find_param);

static int parse_feature_irqs(struct build_feature_devs_info *binfo,
			      resource_size_t ofst, struct dfl_feature_info *finfo)
{
	void __iomem *base = binfo->ioaddr + ofst;
	unsigned int i, ibase, inr = 0;
	void *params = finfo->params;
	enum dfl_id_type type;
	u16 fid = finfo->fid;
	int virq;
	u64 *p;
	u64 v;

	switch (finfo->dfh_version) {
	case 0:
		/*
		 * DFHv0 only provides MMIO resource information for each feature
		 * in the DFL header.  There is no generic interrupt information.
		 * Instead, features with interrupt functionality provide
		 * the information in feature specific registers.
		 */
		type = binfo->type;
		if (type == PORT_ID) {
			switch (fid) {
			case PORT_FEATURE_ID_UINT:
				v = readq(base + PORT_UINT_CAP);
				ibase = FIELD_GET(PORT_UINT_CAP_FST_VECT, v);
				inr = FIELD_GET(PORT_UINT_CAP_INT_NUM, v);
				break;
			case PORT_FEATURE_ID_ERROR:
				v = readq(base + PORT_ERROR_CAP);
				ibase = FIELD_GET(PORT_ERROR_CAP_INT_VECT, v);
				inr = FIELD_GET(PORT_ERROR_CAP_SUPP_INT, v);
				break;
			}
		} else if (type == FME_ID) {
			switch (fid) {
			case FME_FEATURE_ID_GLOBAL_ERR:
				v = readq(base + FME_ERROR_CAP);
				ibase = FIELD_GET(FME_ERROR_CAP_INT_VECT, v);
				inr = FIELD_GET(FME_ERROR_CAP_SUPP_INT, v);
				break;
			}
		}
		break;

	case 1:
		/*
		 * DFHv1 provides interrupt resource information in DFHv1
		 * parameter blocks.
		 */
		p = find_param(params, finfo->param_size, DFHv1_PARAM_ID_MSI_X);
		if (!p)
			break;

		p++;
		ibase = FIELD_GET(DFHv1_PARAM_MSI_X_STARTV, *p);
		inr = FIELD_GET(DFHv1_PARAM_MSI_X_NUMV, *p);
		break;

	default:
		dev_warn(binfo->dev, "unexpected DFH version %d\n", finfo->dfh_version);
		break;
	}

	if (!inr) {
		finfo->irq_base = 0;
		finfo->nr_irqs = 0;
		return 0;
	}

	dev_dbg(binfo->dev, "feature: 0x%x, irq_base: %u, nr_irqs: %u\n",
		fid, ibase, inr);

	if (ibase + inr > binfo->nr_irqs) {
		dev_err(binfo->dev,
			"Invalid interrupt number in feature 0x%x\n", fid);
		return -EINVAL;
	}

	for (i = 0; i < inr; i++) {
		virq = binfo->irq_table[ibase + i];
		if (virq < 0 || virq > NR_IRQS) {
			dev_err(binfo->dev,
				"Invalid irq table entry for feature 0x%x\n",
				fid);
			return -EINVAL;
		}
	}

	finfo->irq_base = ibase;
	finfo->nr_irqs = inr;

	return 0;
}

static int dfh_get_param_size(void __iomem *dfh_base, resource_size_t max)
{
	int size = 0;
	u64 v, next;

	if (!FIELD_GET(DFHv1_CSR_SIZE_GRP_HAS_PARAMS,
		       readq(dfh_base + DFHv1_CSR_SIZE_GRP)))
		return 0;

	while (size + DFHv1_PARAM_HDR < max) {
		v = readq(dfh_base + DFHv1_PARAM_HDR + size);

		next = FIELD_GET(DFHv1_PARAM_HDR_NEXT_OFFSET, v);
		if (!next)
			return -EINVAL;

		size += next * sizeof(u64);

		if (FIELD_GET(DFHv1_PARAM_HDR_NEXT_EOP, v))
			return size;
	}

	return -ENOENT;
}

/*
 * when create sub feature instances, for private features, it doesn't need
 * to provide resource size and feature id as they could be read from DFH
 * register. For afu sub feature, its register region only contains user
 * defined registers, so never trust any information from it, just use the
 * resource size information provided by its parent FIU.
 */
static int
create_feature_instance(struct build_feature_devs_info *binfo,
			resource_size_t ofst, resource_size_t size, u16 fid)
{
	struct dfl_feature_info *finfo;
	resource_size_t start, end;
	int dfh_psize = 0;
	u8 revision = 0;
	u64 v, addr_off;
	u8 dfh_ver = 0;
	int ret;

	if (fid != FEATURE_ID_AFU) {
		v = readq(binfo->ioaddr + ofst);
		revision = FIELD_GET(DFH_REVISION, v);
		dfh_ver = FIELD_GET(DFH_VERSION, v);
		/* read feature size and id if inputs are invalid */
		size = size ? size : feature_size(v);
		fid = fid ? fid : feature_id(v);
		if (dfh_ver == 1) {
			dfh_psize = dfh_get_param_size(binfo->ioaddr + ofst, size);
			if (dfh_psize < 0) {
				dev_err(binfo->dev,
					"failed to read size of DFHv1 parameters %d\n",
					dfh_psize);
				return dfh_psize;
			}
			dev_dbg(binfo->dev, "dfhv1_psize %d\n", dfh_psize);
		}
	}

	if (binfo->len - ofst < size)
		return -EINVAL;

	finfo = kzalloc(struct_size(finfo, params, dfh_psize / sizeof(u64)), GFP_KERNEL);
	if (!finfo)
		return -ENOMEM;

	memcpy_fromio(finfo->params, binfo->ioaddr + ofst + DFHv1_PARAM_HDR, dfh_psize);
	finfo->param_size = dfh_psize;

	finfo->fid = fid;
	finfo->revision = revision;
	finfo->dfh_version = dfh_ver;
	if (dfh_ver == 1) {
		v = readq(binfo->ioaddr + ofst + DFHv1_CSR_ADDR);
		addr_off = FIELD_GET(DFHv1_CSR_ADDR_MASK, v);
		if (FIELD_GET(DFHv1_CSR_ADDR_REL, v))
			start = addr_off << 1;
		else
			start = binfo->start + ofst + addr_off;

		v = readq(binfo->ioaddr + ofst + DFHv1_CSR_SIZE_GRP);
		end = start + FIELD_GET(DFHv1_CSR_SIZE_GRP_SIZE, v) - 1;
	} else {
		start = binfo->start + ofst;
		end = start + size - 1;
	}
	finfo->mmio_res.flags = IORESOURCE_MEM;
	finfo->mmio_res.start = start;
	finfo->mmio_res.end = end;

	ret = parse_feature_irqs(binfo, ofst, finfo);
	if (ret) {
		kfree(finfo);
		return ret;
	}

	list_add_tail(&finfo->node, &binfo->sub_features);
	binfo->feature_num++;

	return 0;
}

static int parse_feature_port_afu(struct build_feature_devs_info *binfo,
				  resource_size_t ofst)
{
	u64 v = readq(binfo->ioaddr + PORT_HDR_CAP);
	u32 size = FIELD_GET(PORT_CAP_MMIO_SIZE, v) << 10;

	WARN_ON(!size);

	return create_feature_instance(binfo, ofst, size, FEATURE_ID_AFU);
}

#define is_feature_dev_detected(binfo) ((binfo)->type != DFL_ID_MAX)

static int parse_feature_afu(struct build_feature_devs_info *binfo,
			     resource_size_t ofst)
{
	if (!is_feature_dev_detected(binfo)) {
		dev_err(binfo->dev, "this AFU does not belong to any FIU.\n");
		return -EINVAL;
	}

	switch (binfo->type) {
	case PORT_ID:
		return parse_feature_port_afu(binfo, ofst);
	default:
		dev_info(binfo->dev, "AFU belonging to FIU is not supported yet.\n");
	}

	return 0;
}

static int build_info_prepare(struct build_feature_devs_info *binfo,
			      resource_size_t start, resource_size_t len)
{
	struct device *dev = binfo->dev;
	void __iomem *ioaddr;

	if (!devm_request_mem_region(dev, start, len, dev_name(dev))) {
		dev_err(dev, "request region fail, start:%pa, len:%pa\n",
			&start, &len);
		return -EBUSY;
	}

	ioaddr = devm_ioremap(dev, start, len);
	if (!ioaddr) {
		dev_err(dev, "ioremap region fail, start:%pa, len:%pa\n",
			&start, &len);
		return -ENOMEM;
	}

	binfo->start = start;
	binfo->len = len;
	binfo->ioaddr = ioaddr;

	return 0;
}

static void build_info_complete(struct build_feature_devs_info *binfo)
{
	devm_iounmap(binfo->dev, binfo->ioaddr);
	devm_release_mem_region(binfo->dev, binfo->start, binfo->len);
}

static int parse_feature_fiu(struct build_feature_devs_info *binfo,
			     resource_size_t ofst)
{
	enum dfl_id_type type;
	int ret = 0;
	u32 offset;
	u16 id;
	u64 v;

	if (is_feature_dev_detected(binfo)) {
		build_info_complete(binfo);

		ret = build_info_commit_dev(binfo);
		if (ret)
			return ret;

		ret = build_info_prepare(binfo, binfo->start + ofst,
					 binfo->len - ofst);
		if (ret)
			return ret;
	}

	v = readq(binfo->ioaddr + DFH);
	id = FIELD_GET(DFH_ID, v);

	type = dfh_id_to_type(id);
	if (type >= DFL_ID_MAX)
		return -EINVAL;

	binfo->type = type;
	binfo->feature_num = 0;
	INIT_LIST_HEAD(&binfo->sub_features);

	ret = create_feature_instance(binfo, 0, 0, 0);
	if (ret)
		return ret;
	/*
	 * find and parse FIU's child AFU via its NEXT_AFU register.
	 * please note that only Port has valid NEXT_AFU pointer per spec.
	 */
	v = readq(binfo->ioaddr + NEXT_AFU);

	offset = FIELD_GET(NEXT_AFU_NEXT_DFH_OFST, v);
	if (offset)
		return parse_feature_afu(binfo, offset);

	dev_dbg(binfo->dev, "No AFUs detected on FIU %d\n", id);

	return ret;
}

static int parse_feature_private(struct build_feature_devs_info *binfo,
				 resource_size_t ofst)
{
	if (!is_feature_dev_detected(binfo)) {
		dev_err(binfo->dev, "the private feature 0x%x does not belong to any AFU.\n",
			feature_id(readq(binfo->ioaddr + ofst)));
		return -EINVAL;
	}

	return create_feature_instance(binfo, ofst, 0, 0);
}

/**
 * parse_feature - parse a feature on given device feature list
 *
 * @binfo: build feature devices information.
 * @ofst: offset to current FIU header
 */
static int parse_feature(struct build_feature_devs_info *binfo,
			 resource_size_t ofst)
{
	u64 v;
	u32 type;

	v = readq(binfo->ioaddr + ofst + DFH);
	type = FIELD_GET(DFH_TYPE, v);

	switch (type) {
	case DFH_TYPE_AFU:
		return parse_feature_afu(binfo, ofst);
	case DFH_TYPE_PRIVATE:
		return parse_feature_private(binfo, ofst);
	case DFH_TYPE_FIU:
		return parse_feature_fiu(binfo, ofst);
	default:
		dev_info(binfo->dev,
			 "Feature Type %x is not supported.\n", type);
	}

	return 0;
}

static int parse_feature_list(struct build_feature_devs_info *binfo,
			      resource_size_t start, resource_size_t len)
{
	resource_size_t end = start + len;
	int ret = 0;
	u32 ofst = 0;
	u64 v;

	ret = build_info_prepare(binfo, start, len);
	if (ret)
		return ret;

	/* walk through the device feature list via DFH's next DFH pointer. */
	for (; start < end; start += ofst) {
		if (end - start < DFH_SIZE) {
			dev_err(binfo->dev, "The region is too small to contain a feature.\n");
			return -EINVAL;
		}

		ret = parse_feature(binfo, start - binfo->start);
		if (ret)
			return ret;

		v = readq(binfo->ioaddr + start - binfo->start + DFH);
		ofst = FIELD_GET(DFH_NEXT_HDR_OFST, v);

		/* stop parsing if EOL(End of List) is set or offset is 0 */
		if ((v & DFH_EOL) || !ofst)
			break;
	}

	/* commit current feature device when reach the end of list */
	build_info_complete(binfo);

	if (is_feature_dev_detected(binfo))
		ret = build_info_commit_dev(binfo);

	return ret;
}

struct dfl_fpga_enum_info *dfl_fpga_enum_info_alloc(struct device *dev)
{
	struct dfl_fpga_enum_info *info;

	get_device(dev);

	info = devm_kzalloc(dev, sizeof(*info), GFP_KERNEL);
	if (!info) {
		put_device(dev);
		return NULL;
	}

	info->dev = dev;
	INIT_LIST_HEAD(&info->dfls);

	return info;
}
EXPORT_SYMBOL_GPL(dfl_fpga_enum_info_alloc);

void dfl_fpga_enum_info_free(struct dfl_fpga_enum_info *info)
{
	struct dfl_fpga_enum_dfl *tmp, *dfl;
	struct device *dev;

	if (!info)
		return;

	dev = info->dev;

	/* remove all device feature lists in the list. */
	list_for_each_entry_safe(dfl, tmp, &info->dfls, node) {
		list_del(&dfl->node);
		devm_kfree(dev, dfl);
	}

	/* remove irq table */
	if (info->irq_table)
		devm_kfree(dev, info->irq_table);

	devm_kfree(dev, info);
	put_device(dev);
}
EXPORT_SYMBOL_GPL(dfl_fpga_enum_info_free);

/**
 * dfl_fpga_enum_info_add_dfl - add info of a device feature list to enum info
 *
 * @info: ptr to dfl_fpga_enum_info
 * @start: mmio resource address of the device feature list.
 * @len: mmio resource length of the device feature list.
 *
 * One FPGA device may have one or more Device Feature Lists (DFLs), use this
 * function to add information of each DFL to common data structure for next
 * step enumeration.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int dfl_fpga_enum_info_add_dfl(struct dfl_fpga_enum_info *info,
			       resource_size_t start, resource_size_t len)
{
	struct dfl_fpga_enum_dfl *dfl;

	dfl = devm_kzalloc(info->dev, sizeof(*dfl), GFP_KERNEL);
	if (!dfl)
		return -ENOMEM;

	dfl->start = start;
	dfl->len = len;

	list_add_tail(&dfl->node, &info->dfls);

	return 0;
}
EXPORT_SYMBOL_GPL(dfl_fpga_enum_info_add_dfl);

/**
 * dfl_fpga_enum_info_add_irq - add irq table to enum info
 *
 * @info: ptr to dfl_fpga_enum_info
 * @nr_irqs: number of irqs of the DFL fpga device to be enumerated.
 * @irq_table: Linux IRQ numbers for all irqs, indexed by local irq index of
 *	       this device.
 *
 * One FPGA device may have several interrupts. This function adds irq
 * information of the DFL fpga device to enum info for next step enumeration.
 * This function should be called before dfl_fpga_feature_devs_enumerate().
 * As we only support one irq domain for all DFLs in the same enum info, adding
 * irq table a second time for the same enum info will return error.
 *
 * If we need to enumerate DFLs which belong to different irq domains, we
 * should fill more enum info and enumerate them one by one.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int dfl_fpga_enum_info_add_irq(struct dfl_fpga_enum_info *info,
			       unsigned int nr_irqs, int *irq_table)
{
	if (!nr_irqs || !irq_table)
		return -EINVAL;

	if (info->irq_table)
		return -EEXIST;

	info->irq_table = devm_kmemdup(info->dev, irq_table,
				       sizeof(int) * nr_irqs, GFP_KERNEL);
	if (!info->irq_table)
		return -ENOMEM;

	info->nr_irqs = nr_irqs;

	return 0;
}
EXPORT_SYMBOL_GPL(dfl_fpga_enum_info_add_irq);

static int remove_feature_dev(struct device *dev, void *data)
{
	struct dfl_feature_dev_data *fdata = to_dfl_feature_dev_data(dev);

	feature_dev_unregister(fdata);

	return 0;
}

static void remove_feature_devs(struct dfl_fpga_cdev *cdev)
{
	device_for_each_child(&cdev->region->dev, NULL, remove_feature_dev);
}

/**
 * dfl_fpga_feature_devs_enumerate - enumerate feature devices
 * @info: information for enumeration.
 *
 * This function creates a container device (base FPGA region), enumerates
 * feature devices based on the enumeration info and creates platform devices
 * under the container device.
 *
 * Return: dfl_fpga_cdev struct on success, -errno on failure
 */
struct dfl_fpga_cdev *
dfl_fpga_feature_devs_enumerate(struct dfl_fpga_enum_info *info)
{
	struct build_feature_devs_info *binfo;
	struct dfl_fpga_enum_dfl *dfl;
	struct dfl_fpga_cdev *cdev;
	int ret = 0;

	if (!info->dev)
		return ERR_PTR(-ENODEV);

	cdev = devm_kzalloc(info->dev, sizeof(*cdev), GFP_KERNEL);
	if (!cdev)
		return ERR_PTR(-ENOMEM);

	cdev->parent = info->dev;
	mutex_init(&cdev->lock);
	INIT_LIST_HEAD(&cdev->port_dev_list);

	cdev->region = fpga_region_register(info->dev, NULL, NULL);
	if (IS_ERR(cdev->region)) {
		ret = PTR_ERR(cdev->region);
		goto free_cdev_exit;
	}

	/* create and init build info for enumeration */
	binfo = devm_kzalloc(info->dev, sizeof(*binfo), GFP_KERNEL);
	if (!binfo) {
		ret = -ENOMEM;
		goto unregister_region_exit;
	}

	binfo->type = DFL_ID_MAX;
	binfo->dev = info->dev;
	binfo->cdev = cdev;

	binfo->nr_irqs = info->nr_irqs;
	if (info->nr_irqs)
		binfo->irq_table = info->irq_table;

	/*
	 * start enumeration for all feature devices based on Device Feature
	 * Lists.
	 */
	list_for_each_entry(dfl, &info->dfls, node) {
		ret = parse_feature_list(binfo, dfl->start, dfl->len);
		if (ret) {
			remove_feature_devs(cdev);
			build_info_free(binfo);
			goto unregister_region_exit;
		}
	}

	build_info_free(binfo);

	return cdev;

unregister_region_exit:
	fpga_region_unregister(cdev->region);
free_cdev_exit:
	devm_kfree(info->dev, cdev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(dfl_fpga_feature_devs_enumerate);

/**
 * dfl_fpga_feature_devs_remove - remove all feature devices
 * @cdev: fpga container device.
 *
 * Remove the container device and all feature devices under given container
 * devices.
 */
void dfl_fpga_feature_devs_remove(struct dfl_fpga_cdev *cdev)
{
	mutex_lock(&cdev->lock);
	if (cdev->fme_dev)
		put_device(cdev->fme_dev);

	mutex_unlock(&cdev->lock);

	remove_feature_devs(cdev);

	fpga_region_unregister(cdev->region);
	devm_kfree(cdev->parent, cdev);
}
EXPORT_SYMBOL_GPL(dfl_fpga_feature_devs_remove);

/**
 * __dfl_fpga_cdev_find_port_data - find a port under given container device
 *
 * @cdev: container device
 * @data: data passed to match function
 * @match: match function used to find specific port from the port device list
 *
 * Find a port device under container device. This function needs to be
 * invoked with lock held.
 *
 * Return: pointer to port's platform device if successful, NULL otherwise.
 *
 * NOTE: you will need to drop the device reference with put_device() after use.
 */
struct dfl_feature_dev_data *
__dfl_fpga_cdev_find_port_data(struct dfl_fpga_cdev *cdev, void *data,
			       int (*match)(struct dfl_feature_dev_data *, void *))
{
	struct dfl_feature_dev_data *fdata;

	list_for_each_entry(fdata, &cdev->port_dev_list, node) {
		if (match(fdata, data))
			return fdata;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(__dfl_fpga_cdev_find_port_data);

static int __init dfl_fpga_init(void)
{
	int ret;

	ret = bus_register(&dfl_bus_type);
	if (ret)
		return ret;

	dfl_ids_init();

	ret = dfl_chardev_init();
	if (ret) {
		dfl_ids_destroy();
		bus_unregister(&dfl_bus_type);
	}

	return ret;
}

/**
 * dfl_fpga_cdev_release_port - release a port platform device
 *
 * @cdev: parent container device.
 * @port_id: id of the port platform device.
 *
 * This function allows user to release a port platform device. This is a
 * mandatory step before turn a port from PF into VF for SRIOV support.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int dfl_fpga_cdev_release_port(struct dfl_fpga_cdev *cdev, int port_id)
{
	struct dfl_feature_dev_data *fdata;
	int ret = -ENODEV;

	mutex_lock(&cdev->lock);
	fdata = __dfl_fpga_cdev_find_port_data(cdev, &port_id,
					       dfl_fpga_check_port_id);
	if (!fdata)
		goto unlock_exit;

	if (!fdata->dev) {
		ret = -EBUSY;
		goto unlock_exit;
	}

	mutex_lock(&fdata->lock);
	ret = dfl_feature_dev_use_begin(fdata, true);
	mutex_unlock(&fdata->lock);
	if (ret)
		goto unlock_exit;

	feature_dev_unregister(fdata);
	cdev->released_port_num++;
unlock_exit:
	mutex_unlock(&cdev->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(dfl_fpga_cdev_release_port);

/**
 * dfl_fpga_cdev_assign_port - assign a port platform device back
 *
 * @cdev: parent container device.
 * @port_id: id of the port platform device.
 *
 * This function allows user to assign a port platform device back. This is
 * a mandatory step after disable SRIOV support.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int dfl_fpga_cdev_assign_port(struct dfl_fpga_cdev *cdev, int port_id)
{
	struct dfl_feature_dev_data *fdata;
	int ret = -ENODEV;

	mutex_lock(&cdev->lock);
	fdata = __dfl_fpga_cdev_find_port_data(cdev, &port_id,
					       dfl_fpga_check_port_id);
	if (!fdata)
		goto unlock_exit;

	if (fdata->dev) {
		ret = -EBUSY;
		goto unlock_exit;
	}

	ret = feature_dev_register(fdata);
	if (ret)
		goto unlock_exit;

	mutex_lock(&fdata->lock);
	dfl_feature_dev_use_end(fdata);
	mutex_unlock(&fdata->lock);

	cdev->released_port_num--;
unlock_exit:
	mutex_unlock(&cdev->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(dfl_fpga_cdev_assign_port);

static void config_port_access_mode(struct device *fme_dev, int port_id,
				    bool is_vf)
{
	struct dfl_feature_dev_data *fdata = to_dfl_feature_dev_data(fme_dev);
	void __iomem *base;
	u64 v;

	base = dfl_get_feature_ioaddr_by_id(fdata, FME_FEATURE_ID_HEADER);

	v = readq(base + FME_HDR_PORT_OFST(port_id));

	v &= ~FME_PORT_OFST_ACC_CTRL;
	v |= FIELD_PREP(FME_PORT_OFST_ACC_CTRL,
			is_vf ? FME_PORT_OFST_ACC_VF : FME_PORT_OFST_ACC_PF);

	writeq(v, base + FME_HDR_PORT_OFST(port_id));
}

#define config_port_vf_mode(dev, id) config_port_access_mode(dev, id, true)
#define config_port_pf_mode(dev, id) config_port_access_mode(dev, id, false)

/**
 * dfl_fpga_cdev_config_ports_pf - configure ports to PF access mode
 *
 * @cdev: parent container device.
 *
 * This function is needed in sriov configuration routine. It could be used to
 * configure the all released ports from VF access mode to PF.
 */
void dfl_fpga_cdev_config_ports_pf(struct dfl_fpga_cdev *cdev)
{
	struct dfl_feature_dev_data *fdata;

	mutex_lock(&cdev->lock);
	list_for_each_entry(fdata, &cdev->port_dev_list, node) {
		if (fdata->dev)
			continue;

		config_port_pf_mode(cdev->fme_dev, fdata->id);
	}
	mutex_unlock(&cdev->lock);
}
EXPORT_SYMBOL_GPL(dfl_fpga_cdev_config_ports_pf);

/**
 * dfl_fpga_cdev_config_ports_vf - configure ports to VF access mode
 *
 * @cdev: parent container device.
 * @num_vfs: VF device number.
 *
 * This function is needed in sriov configuration routine. It could be used to
 * configure the released ports from PF access mode to VF.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int dfl_fpga_cdev_config_ports_vf(struct dfl_fpga_cdev *cdev, int num_vfs)
{
	struct dfl_feature_dev_data *fdata;
	int ret = 0;

	mutex_lock(&cdev->lock);
	/*
	 * can't turn multiple ports into 1 VF device, only 1 port for 1 VF
	 * device, so if released port number doesn't match VF device number,
	 * then reject the request with -EINVAL error code.
	 */
	if (cdev->released_port_num != num_vfs) {
		ret = -EINVAL;
		goto done;
	}

	list_for_each_entry(fdata, &cdev->port_dev_list, node) {
		if (fdata->dev)
			continue;

		config_port_vf_mode(cdev->fme_dev, fdata->id);
	}
done:
	mutex_unlock(&cdev->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(dfl_fpga_cdev_config_ports_vf);

static irqreturn_t dfl_irq_handler(int irq, void *arg)
{
	struct eventfd_ctx *trigger = arg;

	eventfd_signal(trigger);
	return IRQ_HANDLED;
}

static int do_set_irq_trigger(struct dfl_feature *feature, unsigned int idx,
			      int fd)
{
	struct platform_device *pdev = feature->dev;
	struct eventfd_ctx *trigger;
	int irq, ret;

	irq = feature->irq_ctx[idx].irq;

	if (feature->irq_ctx[idx].trigger) {
		free_irq(irq, feature->irq_ctx[idx].trigger);
		kfree(feature->irq_ctx[idx].name);
		eventfd_ctx_put(feature->irq_ctx[idx].trigger);
		feature->irq_ctx[idx].trigger = NULL;
	}

	if (fd < 0)
		return 0;

	feature->irq_ctx[idx].name =
		kasprintf(GFP_KERNEL, "fpga-irq[%u](%s-%x)", idx,
			  dev_name(&pdev->dev), feature->id);
	if (!feature->irq_ctx[idx].name)
		return -ENOMEM;

	trigger = eventfd_ctx_fdget(fd);
	if (IS_ERR(trigger)) {
		ret = PTR_ERR(trigger);
		goto free_name;
	}

	ret = request_irq(irq, dfl_irq_handler, 0,
			  feature->irq_ctx[idx].name, trigger);
	if (!ret) {
		feature->irq_ctx[idx].trigger = trigger;
		return ret;
	}

	eventfd_ctx_put(trigger);
free_name:
	kfree(feature->irq_ctx[idx].name);

	return ret;
}

/**
 * dfl_fpga_set_irq_triggers - set eventfd triggers for dfl feature interrupts
 *
 * @feature: dfl sub feature.
 * @start: start of irq index in this dfl sub feature.
 * @count: number of irqs.
 * @fds: eventfds to bind with irqs. unbind related irq if fds[n] is negative.
 *	 unbind "count" specified number of irqs if fds ptr is NULL.
 *
 * Bind given eventfds with irqs in this dfl sub feature. Unbind related irq if
 * fds[n] is negative. Unbind "count" specified number of irqs if fds ptr is
 * NULL.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int dfl_fpga_set_irq_triggers(struct dfl_feature *feature, unsigned int start,
			      unsigned int count, int32_t *fds)
{
	unsigned int i;
	int ret = 0;

	/* overflow */
	if (unlikely(start + count < start))
		return -EINVAL;

	/* exceeds nr_irqs */
	if (start + count > feature->nr_irqs)
		return -EINVAL;

	for (i = 0; i < count; i++) {
		int fd = fds ? fds[i] : -1;

		ret = do_set_irq_trigger(feature, start + i, fd);
		if (ret) {
			while (i--)
				do_set_irq_trigger(feature, start + i, -1);
			break;
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(dfl_fpga_set_irq_triggers);

/**
 * dfl_feature_ioctl_get_num_irqs - dfl feature _GET_IRQ_NUM ioctl interface.
 * @pdev: the feature device which has the sub feature
 * @feature: the dfl sub feature
 * @arg: ioctl argument
 *
 * Return: 0 on success, negative error code otherwise.
 */
long dfl_feature_ioctl_get_num_irqs(struct platform_device *pdev,
				    struct dfl_feature *feature,
				    unsigned long arg)
{
	return put_user(feature->nr_irqs, (__u32 __user *)arg);
}
EXPORT_SYMBOL_GPL(dfl_feature_ioctl_get_num_irqs);

/**
 * dfl_feature_ioctl_set_irq - dfl feature _SET_IRQ ioctl interface.
 * @pdev: the feature device which has the sub feature
 * @feature: the dfl sub feature
 * @arg: ioctl argument
 *
 * Return: 0 on success, negative error code otherwise.
 */
long dfl_feature_ioctl_set_irq(struct platform_device *pdev,
			       struct dfl_feature *feature,
			       unsigned long arg)
{
	struct dfl_feature_dev_data *fdata = to_dfl_feature_dev_data(&pdev->dev);
	struct dfl_fpga_irq_set hdr;
	s32 *fds;
	long ret;

	if (!feature->nr_irqs)
		return -ENOENT;

	if (copy_from_user(&hdr, (void __user *)arg, sizeof(hdr)))
		return -EFAULT;

	if (!hdr.count || (hdr.start + hdr.count > feature->nr_irqs) ||
	    (hdr.start + hdr.count < hdr.start))
		return -EINVAL;

	fds = memdup_array_user((void __user *)(arg + sizeof(hdr)),
				hdr.count, sizeof(s32));
	if (IS_ERR(fds))
		return PTR_ERR(fds);

	mutex_lock(&fdata->lock);
	ret = dfl_fpga_set_irq_triggers(feature, hdr.start, hdr.count, fds);
	mutex_unlock(&fdata->lock);

	kfree(fds);
	return ret;
}
EXPORT_SYMBOL_GPL(dfl_feature_ioctl_set_irq);

static void __exit dfl_fpga_exit(void)
{
	dfl_chardev_uinit();
	dfl_ids_destroy();
	bus_unregister(&dfl_bus_type);
}

module_init(dfl_fpga_init);
module_exit(dfl_fpga_exit);

MODULE_DESCRIPTION("FPGA Device Feature List (DFL) Support");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
