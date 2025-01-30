/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2024 Intel Corporation
 */

#ifndef _XE_GSC_DEBUGFS_H_
#define _XE_GSC_DEBUGFS_H_

#include <linux/debugfs.h>

struct dentry;
struct xe_gsc;

void xe_gsc_debugfs_register(struct xe_gsc *gsc, struct debugfs_node *parent);

#endif
