// SPDX-License-Identifier: GPL-2.0-only
/*
 *  inode.c - part of tracefs, a pseudo file system for activating tracing
 *
 * Based on debugfs by: Greg Kroah-Hartman <greg@kroah.com>
 *
 *  Copyright (C) 2014 Red Hat Inc, author: Steven Rostedt <srostedt@redhat.com>
 *
 * tracefs is the file system that is used by the tracing infrastructure.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/kobject.h>
#include <linux/namei.h>
#include <linux/tracefs.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include "internal.h"

#define TRACEFS_DEFAULT_MODE	0700
static struct kernfs_root *tracefs_root;
static struct kernfs_node *tracefs_kfs_root_node;

static struct vfsmount *tracefs_mount;
static int tracefs_mount_count;
static bool tracefs_registered;

/*
 * Keep track of all tracefs_inodes in order to update their
 * flags if necessary on a remount.
 */
static DEFINE_SPINLOCK(tracefs_inode_lock);
static LIST_HEAD(tracefs_inodes);

static ssize_t tracefs_kf_default_read(struct kernfs_open_file *of, char *buf,
				       size_t count, loff_t pos)
{
	return 0;
}

static ssize_t tracefs_kf_default_write(struct kernfs_open_file *of, char *buf,
					size_t count, loff_t pos)
{
	return 0;
}

static loff_t tracefs_kf_default_llseek(struct kernfs_open_file *of,
					loff_t offset, int whence)
{
	return noop_llseek(of->file, offset, whence);
}

static int tracefs_kf_default_open(struct kernfs_open_file *of)
{
	return 0;
}

static const struct kernfs_ops tracefs_default_file_kfops = {
	.read		= tracefs_kf_default_read,
	.write		= tracefs_kf_default_write,
	.open		= tracefs_kf_default_open,
	.llseek		= tracefs_kf_default_llseek,
};

static struct tracefs_dir_ops {
	int (*mkdir)(const char *name);
	int (*rmdir)(const char *name);
} tracefs_ops __ro_after_init;

struct inode *tracefs_get_inode(struct super_block *sb)
{
	struct inode *inode = new_inode(sb);
	if (inode) {
		inode->i_ino = get_next_ino();
		simple_inode_init_ts(inode);
	}
	return inode;
}

struct tracefs_fs_info {
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	/* Opt_* bitfield. */
	unsigned int opts;
};

/* Why do we have global _and_ stuffed into tracefs_context? */
static struct tracefs_fs_info global_info = {
	.mode	= TRACEFS_DEFAULT_MODE,
	.uid	= GLOBAL_ROOT_UID,
	.gid	= GLOBAL_ROOT_GID,
	.opts	= 0,
};

enum {
	Opt_uid,
	Opt_gid,
	Opt_mode,
};

static const struct fs_parameter_spec tracefs_param_specs[] = {
	fsparam_gid	("gid",		Opt_gid),
	fsparam_u32oct	("mode",	Opt_mode),
	fsparam_uid	("uid",		Opt_uid),
	{}
};

struct tracefs_context {
	struct kernfs_fs_context kfc;
 	struct tracefs_fs_info fs_info;
};

static inline struct tracefs_context *trace_fc2context(struct fs_context *fc)
{
	struct kernfs_fs_context *kfc = fc->fs_private;

	return container_of(kfc, struct tracefs_context, kfc);
}

static int tracefs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct tracefs_context *ctx = trace_fc2context(fc);
	struct tracefs_fs_info *info = &ctx->fs_info;
	struct fs_parse_result result;

	int opt;

	opt = fs_parse(fc, tracefs_param_specs, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_uid:
		info->uid = result.uid;
		break;
	case Opt_gid:
		info->gid = result.gid;
		break;
	case Opt_mode:
		info->mode = result.uint_32 & S_IALLUGO;
		break;
	/*
	 * We might like to report bad mount options here;
	 * but traditionally tracefs has ignored all mount options
	 */
	}

	info->opts |= BIT(opt);

	return 0;
}

static int tracefs_apply_options(struct super_block *sb, bool remount)
{
	struct inode *inode = d_inode(sb->s_root);
	struct tracefs_inode *ti;
	bool update_uid, update_gid;
	umode_t tmp_mode;

	kuid_t kuid = global_info.uid;
	kgid_t kgid = global_info.gid;
	umode_t mode = global_info.mode;
	unsigned int opts = global_info.opts;

	/*
	 * On remount, only reset mode/uid/gid if they were provided as mount
	 * options.
	 */

	if (!remount || opts & BIT(Opt_mode)) {
		tmp_mode = READ_ONCE(inode->i_mode) & ~S_IALLUGO;
		tmp_mode |= mode;
		WRITE_ONCE(inode->i_mode, tmp_mode);
	}

	if (!remount || opts & BIT(Opt_uid))
		inode->i_uid = kuid;

	if (!remount || opts & BIT(Opt_gid))
		inode->i_gid = kgid;

	if (remount && (opts & BIT(Opt_uid) || opts & BIT(Opt_gid))) {

		update_uid = opts & BIT(Opt_uid);
		update_gid = opts & BIT(Opt_gid);

		rcu_read_lock();
		list_for_each_entry_rcu(ti, &tracefs_inodes, list) {
			if (update_uid) {
				ti->flags &= ~TRACEFS_UID_PERM_SET;
				ti->vfs_inode.i_uid = kuid;
			}

			if (update_gid) {
				ti->flags &= ~TRACEFS_GID_PERM_SET;
				ti->vfs_inode.i_gid = kgid;
			}

			/*
			 * Note, the above ti->vfs_inode updates are
			 * used in eventfs_remount() so they must come
			 * before calling it.
			 */
			if (ti->flags & TRACEFS_EVENT_INODE)
				eventfs_remount(ti, update_uid, update_gid);
		}
		rcu_read_unlock();
	}

	return 0;
}

/* TODO: Christian had most of this function nuked */
static int tracefs_reconfigure(struct fs_context *fc)
{
	struct super_block *sb = fc->root->d_sb;
	struct tracefs_fs_info *sb_opts = sb->s_fs_info;
	struct tracefs_fs_info *new_opts = fc->s_fs_info;

	if (!new_opts)
		return 0;

	/* TODO: Do we need sync_filesystem with kernfs? */
	sync_filesystem(sb);
	/* structure copy of new mount options to sb */
	*sb_opts = *new_opts;

	return tracefs_apply_options(sb, true);
}

static int tracefs_show_options(struct seq_file *seq, struct kernfs_root *kf_root)
{
	kuid_t kuid = global_info.uid;
	kgid_t kgid = global_info.gid;
	umode_t mode = global_info.mode;

	if (!uid_eq(kuid, GLOBAL_ROOT_UID))
		seq_printf(seq, ",uid=%u", from_kuid_munged(&init_user_ns, kuid));
	if (!gid_eq(kgid, GLOBAL_ROOT_GID))
		seq_printf(seq, ",gid=%u", from_kgid_munged(&init_user_ns, kgid));
	if (mode != TRACEFS_DEFAULT_MODE)
		seq_printf(seq, ",mode=%o", mode);

	return 0;
 }

static int tracefs_mkdir(struct kernfs_node *parent_kn, const char *name, umode_t mode)
 {
	int ret;
	struct kernfs_node *kn;

	if (parent_kn != trace_instance_dir)
		return -EPERM;

	kn = tracefs_create_dir(name, parent_kn);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	ret = tracefs_ops.mkdir(name);
	if (ret)
		kernfs_remove(kn);
	return ret;
}

static int tracefs_rmdir(struct kernfs_node *kn)
 {
	int ret;

	if (kn != trace_instance_dir)
		return -EPERM;

 	ret = tracefs_ops.rmdir(kn->name);
	if (!ret)
		kernfs_remove(kn);

	return ret;
}

/*
 * It would be cleaner if eventfs had its own dentry ops.
 *
 * Note that d_revalidate is called potentially under RCU,
 * so it can't take the eventfs mutex etc. It's fine - if
 * we open a file just as it's marked dead, things will
 * still work just fine, and just see the old stale case.
 */
static void tracefs_d_release(struct dentry *dentry)
{
	if (dentry->d_fsdata)
		eventfs_d_release(dentry);
}

static int tracefs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct eventfs_inode *ei = dentry->d_fsdata;

	return !(ei && ei->is_freed);
}

/* necessary for eventsfs */
static const struct dentry_operations tracefs_dentry_operations = {
	.d_revalidate = tracefs_d_revalidate,
	.d_release = tracefs_d_release,
};

static struct kernfs_syscall_ops tracefs_kf_syscall_ops = {
	.show_options		= tracefs_show_options,
	.mkdir			= tracefs_mkdir,
	.rmdir			= tracefs_rmdir,
};

static int tracefs_get_tree(struct fs_context *fc)
{
	int ret;

	ret = kernfs_get_tree(fc);
	if (!ret)
		tracefs_apply_options(fc->root->d_sb, false);

	return ret;
}

static void tracefs_free_fc(struct fs_context *fc)
{
	struct tracefs_context *ctx = trace_fc2context(fc);
	kernfs_free_fs_context(fc);
	kfree(ctx);
}

static const struct fs_context_operations tracefs_context_ops = {
	.free		= tracefs_free_fc,
	.parse_param	= tracefs_parse_param,
	.get_tree	= tracefs_get_tree,
	.reconfigure	= tracefs_reconfigure,
};

static int tracefs_init_fs_context(struct fs_context *fc)
{
	struct tracefs_fs_info *fsi;

	fsi = kzalloc(sizeof(struct tracefs_fs_info), GFP_KERNEL);
	if (!fsi)
		return -ENOMEM;

	fsi->mode = TRACEFS_DEFAULT_MODE;

	fc->s_fs_info = fsi;
	fc->ops = &tracefs_context_ops;
	return 0;
}

static struct file_system_type tracefs_type = {
	.owner			= THIS_MODULE,
	.name 			="tracefs",
	.init_fs_context 	= tracefs_init_fs_context,
	.parameters		= tracefs_param_specs,
	.kill_sb		= kill_litter_super, /* TODO do we need kill_sb? */
};
MODULE_ALIAS_FS("tracefs");

struct dentry *tracefs_start_creating(const char *name, struct dentry *parent)
{
	struct dentry *dentry;
	int error;

	pr_debug("tracefs: creating file '%s'\n",name);

	error = simple_pin_fs(&tracefs_type, &tracefs_mount,
			      &tracefs_mount_count);
	if (error)
		return ERR_PTR(error);

	/* If the parent is not specified, we create it in the root.
	 * We need the root dentry to do this, which is in the super
	 * block. A pointer to that is in the struct vfsmount that we
	 * have around.
	 */
	if (!parent)
		parent = tracefs_mount->mnt_root;

	inode_lock(d_inode(parent));
	if (unlikely(IS_DEADDIR(d_inode(parent))))
		dentry = ERR_PTR(-ENOENT);
	else
		dentry = lookup_one_len(name, parent, strlen(name));
	if (!IS_ERR(dentry) && d_inode(dentry)) {
		dput(dentry);
		dentry = ERR_PTR(-EEXIST);
	}

	if (IS_ERR(dentry)) {
		inode_unlock(d_inode(parent));
		simple_release_fs(&tracefs_mount, &tracefs_mount_count);
	}

	return dentry;
}

struct dentry *tracefs_failed_creating(struct dentry *dentry)
{
	inode_unlock(d_inode(dentry->d_parent));
	dput(dentry);
	simple_release_fs(&tracefs_mount, &tracefs_mount_count);
	return NULL;
}

struct dentry *tracefs_end_creating(struct dentry *dentry)
{
	inode_unlock(d_inode(dentry->d_parent));
	return dentry;
}

/* Find the inode that this will use for default */
static struct inode *instance_inode(struct dentry *parent, struct inode *inode)
{
	struct tracefs_inode *ti;

	/* If parent is NULL then use root inode */
	if (!parent)
		return d_inode(inode->i_sb->s_root);

	/* Find the inode that is flagged as an instance or the root inode */
	while (!IS_ROOT(parent)) {
		ti = get_tracefs(d_inode(parent));
		if (ti->flags & TRACEFS_INSTANCE_INODE)
			break;
		parent = parent->d_parent;
	}

	return d_inode(parent);
}

/**
 * tracefs_create_file - create a file in the tracefs filesystem
 * @name: a pointer to a string containing the name of the file to create.
 * @mode: the permission that the file should have.
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this parameter is NULL, then the
 *          file will be created in the root of the tracefs filesystem.
 * @data: a pointer to something that the caller will want to get to later
 *        on.  The inode.i_private pointer will point to this value on
 *        the open() call.
 * @fops: a pointer to a struct file_operations that should be used for
 *        this file.
 *
 * This is the basic "create a file" function for tracefs.  It allows for a
 * wide range of flexibility in creating a file, or a directory (if you want
 * to create a directory, the tracefs_create_dir() function is
 * recommended to be used instead.)
 *
 * This function will return a pointer to a kernfs_node if it succeeds.  This
 * pointer must be passed to the tracefs_remove() function when the file is
 * to be removed (no automatic cleanup happens if your module is unloaded,
 * you are responsible here.)  If an error occurs, %NULL will be returned.
 *
 * If tracefs is not enabled in the kernel, the value -%ENODEV will be
 * returned.
 */
struct kernfs_node *tracefs_create_file(const char *name, umode_t mode,
					struct kernfs_node *parent, void *data,
					const struct kernfs_ops *ops)
{
	if (security_locked_down(LOCKDOWN_TRACEFS))
		return NULL;

	if (!(mode & S_IFMT))
		mode |= S_IFREG;
	BUG_ON(!S_ISREG(mode));

	/* TODO What is this? */
	// inode->i_op = &tracefs_file_inode_operations;

	return __kernfs_create_file(parent ?: tracefs_kfs_root_node, name, mode,
				    kernfs_node_owner(parent),
				    kernfs_node_group(parent), PAGE_SIZE,
				    ops ? : &tracefs_default_file_kfops, data, NULL,
				    NULL);
}


/**
 * tracefs_create_dir - create a directory in the tracefs filesystem
 * @name: a pointer to a string containing the name of the directory to
 *        create.
 * @parent: a pointer to the parent dentry for this file.  This should be a
 *          directory dentry if set.  If this parameter is NULL, then the
 *          directory will be created in the root of the tracefs filesystem.
 *
 * This function creates a directory in tracefs with the given name.
 *
 * This function will return a pointer to a dentry if it succeeds.  This
 * pointer must be passed to the tracefs_remove() function when the file is
 * to be removed. If an error occurs, %NULL will be returned.
 *
 * If tracing is not enabled in the kernel, the value -%ENODEV will be
 * returned.
 */
struct kernfs_node *tracefs_create_dir(const char *name,
				       struct kernfs_node *parent)
 {
 	if (security_locked_down(LOCKDOWN_TRACEFS))
		return ERR_PTR(-EINVAL);

	return kernfs_create_dir_ns(parent ?: tracefs_kfs_root_node, name,
				  S_IFDIR | S_IRWXU | S_IRUSR | S_IRGRP |
				  S_IXUSR | S_IXGRP,
				  kernfs_node_owner(parent),
				  kernfs_node_group(parent), NULL, NULL);
}

/**
 * tracefs_create_instance_dir - create the tracing instances directory
 * @mkdir: The function to call when a mkdir is performed.
 * @rmdir: The function to call when a rmdir is performed.
 *
 * Only one instances directory is allowed.
 *
 * The instances directory is special as it allows for mkdir and rmdir
 * to be done by userspace. When a mkdir or rmdir is performed, the inode
 * locks are released and the methods passed in (@mkdir and @rmdir) are
 * called without locks and with the name of the directory being created
 * within the instances directory.
 *
 * Returns the dentry of the instances directory.
 */
__init struct kernfs_node *tracefs_create_instance_dir(int (*mkdir)(const char *name),
						       int (*rmdir)(const char *name))
{
	struct kernfs_node *kn;

 	/* Only allow one instance of the instances directory. */
 	if (WARN_ON(tracefs_ops.mkdir || tracefs_ops.rmdir))
		return ERR_PTR(-EINVAL);

	kn = tracefs_create_dir("instances", tracefs_kfs_root_node);
	if (IS_ERR(kn))
		return kn;

 	tracefs_ops.mkdir = mkdir;
 	tracefs_ops.rmdir = rmdir;
	return kn;
}

/**
 * tracefs_remove - recursively removes a directory
 * @kn: a pointer to a the kernfs_node of the directory to be removed.
 *
 * This function recursively removes a directory tree in tracefs that
 * was previously created with a call to another tracefs function
 * (like tracefs_create_file() or variants thereof.)
 */
void tracefs_remove(struct kernfs_node *kn)
{
	if (IS_ERR_OR_NULL(kn))
		return;

	kernfs_remove(kn);
}

/**
 * tracefs_initialized - Tells whether tracefs has been registered
 */
bool tracefs_initialized(void)
{
	return tracefs_registered;
}

static int __init tracefs_init(void)
{
	int retval;
	struct kernfs_root *kfs_root;

	kfs_root = kernfs_create_root(&tracefs_kf_syscall_ops,
				      KERNFS_ROOT_CREATE_DEACTIVATED, NULL);
	if (IS_ERR(kfs_root))
                return PTR_ERR(kfs_root);

	retval = sysfs_create_mount_point(kernel_kobj, "tracing");
	if (retval) {
		kernfs_destroy_root(kfs_root);
		return -EINVAL;
	}

	retval = register_filesystem(&tracefs_type);
	if (!retval)
		tracefs_registered = true;
	else
		kernfs_destroy_root(kfs_root);

	tracefs_root = kfs_root;
	tracefs_kfs_root_node = kernfs_root_to_node(kfs_root);

	return retval;
}
core_initcall(tracefs_init);
