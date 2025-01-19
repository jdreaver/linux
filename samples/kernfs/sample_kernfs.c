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

struct sample_kernfs_directory {
	atomic64_t count;
};

static int sample_kernfs_counter_seq_show(struct seq_file *sf, void *v)
{
	struct kernfs_open_file *of = sf->private;
	struct kernfs_node *dir_kn = kernfs_get_parent(of->kn);
	struct sample_kernfs_directory *counter_dir = dir_kn->priv;

	u64 count = atomic64_inc_return(&counter_dir->count);
	seq_printf(sf, "%llu\n", count);
	return 0;
}

static struct kernfs_ops sample_kernfs_counter_kf_ops = {
	.seq_show	= sample_kernfs_counter_seq_show,
};

static int sample_kernfs_add_counter_file(struct kernfs_node *dir_kn)
{
	struct kernfs_node *kn;
	kn = __kernfs_create_file(dir_kn, "counter", 0666, current_fsuid(),
				  current_fsgid(), 0,
				  &sample_kernfs_counter_kf_ops, NULL,
				  NULL, NULL);

	if (IS_ERR(kn))
		return PTR_ERR(kn);

	return 0;
}

static int sample_kernfs_populate_dir(struct kernfs_node *dir_kn)
{
	// We allocate a struct to hold directory information, which gets
	// stuffed into the private data of the kernfs_node for this directory.
	struct sample_kernfs_directory *dir;
	dir = kzalloc(sizeof(struct sample_kernfs_directory), GFP_KERNEL);
	if (!dir)
		return -ENOMEM;
	dir_kn->priv = dir;

	int err = sample_kernfs_add_counter_file(dir_kn);
	if (err)
		return err;

	return 0;
}

static int sample_kernfs_mkdir(struct kernfs_node *parent_kn, const char *name, umode_t mode)
{
	// N.B. Pass NULL for as the priv argument. It is allocated and assigned
	// in sample_kernfs_populate_dir so the root directory gets it too.
	struct kernfs_node *dir_kn;
	dir_kn = kernfs_create_dir_ns(parent_kn, name, mode, current_fsuid(),
				      current_fsgid(), NULL, NULL);

	if (IS_ERR(dir_kn))
		return PTR_ERR(dir_kn);

	return sample_kernfs_populate_dir(dir_kn);
}

static struct kernfs_syscall_ops sample_kernfs_kf_syscall_ops = {
	.mkdir		= sample_kernfs_mkdir,
};

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
	root = kernfs_create_root(&sample_kernfs_kf_syscall_ops, 0, NULL);
	if (IS_ERR(root))
		return PTR_ERR(root);

	kfc->root = root;
	kfc->magic = SAMPLE_KERNFS_MAGIC;
	fc->fs_private = kfc;
	fc->ops = &sample_kernfs_fs_context_ops;
	fc->global = true;

	int err = sample_kernfs_populate_dir(kernfs_root_to_node(root));
	if (err) {
		kernfs_destroy_root(root);
		return err;
	}

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
