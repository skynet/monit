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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif

#ifdef HAVE_MNTENT_H
#include <mntent.h>
#endif

#include "monit.h"
#include "device_sysdep.h"


char *device_mountpoint_sysdep(char *dev, char *buf, int buflen) {
  FILE *mntfd;
  struct mntent *mnt;

  ASSERT(dev);

  if ((mntfd = setmntent("/etc/mtab", "r")) == NULL) {
    LogError("Cannot open /etc/mtab file\n");
    return NULL;
  }
  while ((mnt = getmntent(mntfd)) != NULL) {
    /* Try to compare the the filesystem as is, if failed, try to use the symbolic link target */
    if (IS(dev, mnt->mnt_fsname) || (realpath(mnt->mnt_fsname, buf) && ! strcasecmp(dev, buf))) {
      snprintf(buf, buflen, "%s", mnt->mnt_dir);
      endmntent(mntfd);
      return buf;
    }
  }
  endmntent(mntfd);
  LogError("Device %s not found in /etc/mtab\n", dev);
  return NULL;
}


int filesystem_usage_sysdep(char *mntpoint, Info_T inf) {
  struct statvfs usage;

  ASSERT(inf);

  if (statvfs(mntpoint, &usage) != 0) {
    LogError("Error getting usage statistics for filesystem '%s' -- %s\n", mntpoint, STRERROR);
    return FALSE;
  }
  inf->priv.filesystem.f_bsize =           usage.f_frsize;
  inf->priv.filesystem.f_blocks =          usage.f_blocks;
  inf->priv.filesystem.f_blocksfree =      usage.f_bavail;
  inf->priv.filesystem.f_blocksfreetotal = usage.f_bfree;
  inf->priv.filesystem.f_files =           usage.f_files;
  inf->priv.filesystem.f_filesfree =       usage.f_ffree;
  inf->priv.filesystem._flags =            inf->priv.filesystem.flags;
  inf->priv.filesystem.flags =             usage.f_flag;
  return TRUE;
}

