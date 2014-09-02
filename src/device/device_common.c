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
 *  System independent filesystem methods.
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
#include <strings.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "monit.h"
#include "device.h"
#include "device_sysdep.h"


int filesystem_usage(Service_T s) {
        ASSERT(s);

        struct stat sb;
        char buf[PATH_MAX+1];
        if (lstat(s->path, &sb) == 0) {
                if (S_ISLNK(sb.st_mode)) {
                        // Symbolic link: dereference so we'll be able to find it in mnttab + get permissions of the target
                        if (! realpath(s->path, buf)) {
                                LogError("filesystem link error -- %s\n", STRERROR);
                                return FALSE;
                        }
                        // Get link target mode + permissions
                        if (stat(buf, &sb) != 0) {
                                LogError("filesystem %s doesn't exist\n", buf);
                                return FALSE;
                        }
                        // If the target is device, get its mountpoint
                        if(S_ISBLK(sb.st_mode) || S_ISCHR(sb.st_mode)) {
                                char dev[PATH_MAX+1];
                                snprintf(dev, sizeof(dev), "%s", buf);
                                if (! device_mountpoint_sysdep(dev, buf, sizeof(buf)))
                                        return FALSE;
                        }
                } else if (S_ISREG(sb.st_mode) || S_ISDIR(sb.st_mode)) {
                        // File or directory: we have mountpoint or filesystem subdirectory already (no need to map)
                        snprintf(buf, sizeof(buf), "%s", s->path);
                } else if(S_ISBLK(sb.st_mode) || S_ISCHR(sb.st_mode)) {
                        // Block or character device: look for mountpoint
                        if (! device_mountpoint_sysdep(s->path, buf, sizeof(buf)))
                                return FALSE;
                } else {
                        LogError("Cannot get filesystem for '%s' -- not file, directory nor device\n", s->path);
                }
        } else {
                // Generic device string (such as sshfs connection info): look for mountpoint
                if (! device_mountpoint_sysdep(s->path, buf, sizeof(buf)))
                        return FALSE;
                if (stat(buf, &sb) != 0) {
                        LogError("filesystem %s doesn't exist\n", buf);
                        return FALSE;
                }
        }
        if (filesystem_usage_sysdep(buf, s->inf)) {
                s->inf->st_mode = sb.st_mode;
                s->inf->st_uid = sb.st_uid;
                s->inf->st_gid = sb.st_gid;
                s->inf->priv.filesystem.inode_percent = s->inf->priv.filesystem.f_files > 0 ? (int)((1000.0 * (s->inf->priv.filesystem.f_files - s->inf->priv.filesystem.f_filesfree)) / (float)s->inf->priv.filesystem.f_files) : 0;
                s->inf->priv.filesystem.space_percent = s->inf->priv.filesystem.f_blocks > 0 ? (int)((1000.0 * (s->inf->priv.filesystem.f_blocks - s->inf->priv.filesystem.f_blocksfree)) / (float)s->inf->priv.filesystem.f_blocks) : 0;
                s->inf->priv.filesystem.inode_total = s->inf->priv.filesystem.f_files - s->inf->priv.filesystem.f_filesfree;
                s->inf->priv.filesystem.space_total = s->inf->priv.filesystem.f_blocks - s->inf->priv.filesystem.f_blocksfreetotal;
                return TRUE;
        }
        return FALSE;
}

