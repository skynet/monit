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

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif

#ifdef HAVE_SYS_MNTTAB_H
# include <sys/mnttab.h>
#endif

#include "monit.h"
#include "device_sysdep.h"


char *device_mountpoint_sysdep(char *dev, char *buf, int buflen) {
        struct mnttab mnt;
        FILE         *mntfd;

        ASSERT(dev);

        if ((mntfd = fopen("/etc/mnttab", "r")) == NULL) {
                LogError("Cannot open /etc/mnttab file\n");
                return NULL;
        }
        while (getmntent(mntfd, &mnt) == 0) {
                if ((realpath(mnt.mnt_special, buf) && IS(buf, dev)) || IS(mnt.mnt_special, dev)) {
                        fclose(mntfd);
                        snprintf(buf, buflen, "%s", mnt.mnt_mountp);
                        return buf;
                }
        }
        fclose(mntfd);
        return NULL;
}


boolean_t filesystem_usage_sysdep(char *mntpoint, Info_T inf) {
        int size;
        struct statvfs usage;

        ASSERT(inf);

        if (statvfs(mntpoint, &usage) != 0) {
                LogError("Error getting usage statistics for filesystem '%s' -- %s\n", mntpoint, STRERROR);
                return false;
        }
        size =                                   usage.f_frsize ? (usage.f_bsize / usage.f_frsize) : 1;
        inf->priv.filesystem.f_bsize =           usage.f_bsize;
        inf->priv.filesystem.f_blocks =          usage.f_blocks / size;
        inf->priv.filesystem.f_blocksfree =      usage.f_bavail / size;
        inf->priv.filesystem.f_blocksfreetotal = usage.f_bfree  / size;
        inf->priv.filesystem.f_files =           usage.f_files;
        inf->priv.filesystem.f_filesfree =       usage.f_ffree;
        inf->priv.filesystem._flags =            inf->priv.filesystem.flags;
        inf->priv.filesystem.flags =             usage.f_flag;
        return true;
}

