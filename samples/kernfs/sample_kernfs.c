// SPDX-License-Identifier: GPL-2.0-only
/*
 * A sample kernel module showing how to build a pseudo-filesystem on top of
 * kernfs.
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/kernfs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#define SAMPLE_KERNFS_MAGIC 0x8d000ff0

static int sample_kernfs_get_tree(struct fs_context *fc)
{
	return kernfs_get_tree(fc);
}

static const struct fs_context_operations sample_kernfs_fs_context_ops = {
	.get_tree	= sample_kernfs_get_tree,
};

static int sample_kernfs_init_fs_context(struct fs_context *fc)
{
	struct kernfs_fs_context *kfc;
	kfc = kzalloc(sizeof(struct kernfs_fs_context), GFP_KERNEL);
	if (!kfc)
		return -ENOMEM;

	struct kernfs_root *root;
	root = kernfs_create_root(NULL, 0, NULL);
	if (IS_ERR(root))
		return PTR_ERR(root);

	kfc->root = root;
	kfc->magic = SAMPLE_KERNFS_MAGIC;
	fc->fs_private = kfc;
	fc->ops = &sample_kernfs_fs_context_ops;
	fc->global = true;

	return 0;
}

static void sample_kernfs_kill_sb(struct super_block *sb)
{
	struct kernfs_root *root = kernfs_root_from_sb(sb);
	kernfs_kill_sb(sb);
	kernfs_destroy_root(root);
}

static struct file_system_type sample_kernfs_fs_type = {
	.name			= "sample_kernfs",
	.init_fs_context	= sample_kernfs_init_fs_context,
	.kill_sb		= sample_kernfs_kill_sb,
	.fs_flags		= FS_USERNS_MOUNT,
};

static int __init sample_kernfs_init(void)
{
	int err = register_filesystem(&sample_kernfs_fs_type);
	if (err)
		return err;

	pr_info("Loaded sample_kernfs module.\n");
	return 0;
}

module_init(sample_kernfs_init)
MODULE_DESCRIPTION("Sample kernel module showing how to use kernfs");
MODULE_LICENSE("GPL");
