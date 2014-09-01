/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU Affero General Public License in all respects
 * for all of the code used other than OpenSSL.
 */

/**
 *  System dependent filesystem methods.
 *
 *  @file
 */

#include "config.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SYS_VFS_H
# include <sys/vfs.h>
#endif

#ifdef HAVE_MNTENT_H
#include <mntent.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "monit.h"
#include "device_sysdep.h"


char *device_mountpoint_sysdep(char *dev, char *buf, int buflen) {
  struct mntent *mnt;
  FILE          *mntfd;

  ASSERT(dev);

  if ((mntfd = setmntent("/etc/mnttab", "r")) == NULL) {
    LogError("Cannot open /etc/mnttab file\n");
    return NULL;
  }
  while ((mnt = getmntent(mntfd)) != NULL) {
    if (IS(dev, mnt->mnt_fsname)) {
      endmntent(mntfd);
      snprintf(buf, buflen, "%s", mnt->mnt_dir);
      return buf;
    }
  }
  endmntent(mntfd);
  return NULL;
}


int filesystem_usage_sysdep(char *mntpoint, Info_T inf) {
  struct statfs usage;

  ASSERT(inf);

  if (statfs(mntpoint, &usage) != 0) {
    LogError("Error getting usage statistics for filesystem '%s' -- %s\n", mntpoint, STRERROR);
    return FALSE;
  }
  inf->priv.filesystem.f_bsize =           usage.f_bsize;
  inf->priv.filesystem.f_blocks =          usage.f_blocks;
  inf->priv.filesystem.f_blocksfree =      usage.f_bavail;
  inf->priv.filesystem.f_blocksfreetotal = usage.f_bfree;
  inf->priv.filesystem.f_files =           usage.f_files;
  inf->priv.filesystem.f_filesfree =       usage.f_ffree;
  return TRUE;
}

