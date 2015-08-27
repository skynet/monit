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

#include "config.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include "monit.h"
#include "engine.h"

// libmonit
#include "io/File.h"

/**
 *  Utilities for managing files used by monit.
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


void file_init() {

        char pidfile[STRLEN];
        char buf[STRLEN];

        /* Check if the pidfile was already set during configfile parsing */
        if (Run.files.pid == NULL) {
                /* Set the location of this programs pidfile */
                if (! getuid()) {
                        snprintf(pidfile, STRLEN, "%s/%s", MYPIDDIR, MYPIDFILE);
                } else {
                        snprintf(pidfile, STRLEN, "%s/.%s", Run.Env.home, MYPIDFILE);
                }
                Run.files.pid = Str_dup(pidfile);
        }

        /* Set the location of monit's id file */
        if (Run.files.id == NULL) {
                snprintf(buf, STRLEN, "%s/.%s", Run.Env.home, MYIDFILE);
                Run.files.id = Str_dup(buf);
        }
        Util_monitId(Run.files.id);

        /* Set the location of monit's state file */
        if (Run.files.state == NULL) {
                snprintf(buf, STRLEN, "%s/.%s", Run.Env.home, MYSTATEFILE);
                Run.files.state = Str_dup(buf);
        }
}


void file_finalize() {
        Engine_cleanup();
        unlink(Run.files.pid);
}


time_t file_getTimestamp(char *object, mode_t type) {

        struct stat buf;

        ASSERT(object);

        if (! stat(object, &buf)) {
                if (((type == S_IFREG) && S_ISREG(buf.st_mode)) ||
                    ((type == S_IFDIR) && S_ISDIR(buf.st_mode)) ||
                    ((type == S_IFSOCK) && S_ISSOCK(buf.st_mode)) ||
                    ((type == (S_IFREG|S_IFDIR)) && (S_ISREG(buf.st_mode) || S_ISDIR(buf.st_mode)))
                    ) {
                        return MAX(buf.st_mtime, buf.st_ctime);
                } else {
                        LogError("Invalid object type - %s\n", object);
                }
        }

        return 0;

}


char *file_findControlFile() {

        char *rcfile = CALLOC(sizeof(char), STRLEN + 1);

        snprintf(rcfile, STRLEN, "%s/.%s", Run.Env.home, MONITRC);
        if (File_exist(rcfile)) {
                return rcfile;
        }
        snprintf(rcfile, STRLEN, "/etc/%s", MONITRC);
        if (File_exist(rcfile)) {
                return rcfile;
        }
        snprintf(rcfile, STRLEN, "%s/%s", SYSCONFDIR, MONITRC);
        if (File_exist(rcfile)) {
                return rcfile;
        }
        snprintf(rcfile, STRLEN, "/usr/local/etc/%s", MONITRC);
        if (File_exist(rcfile)) {
                return rcfile;
        }
        if (File_exist(MONITRC)) {
                snprintf(rcfile, STRLEN, "%s/%s", Run.Env.cwd, MONITRC);
                return rcfile;
        }
        LogError("Cannot find the control file at ~/.%s, /etc/%s, %s/%s, /usr/local/etc/%s or at ./%s \n", MONITRC, MONITRC, SYSCONFDIR, MONITRC, MONITRC, MONITRC);
        exit(1);

}


boolean_t file_createPidFile(char *pidfile) {
        ASSERT(pidfile);

        unlink(pidfile);
        FILE *F = fopen(pidfile, "w");
        if (! F) {
                LogError("Error opening pidfile '%s' for writing -- %s\n", pidfile, STRERROR);
                return false;
        }
        fprintf(F, "%d\n", (int)getpid());
        fclose(F);

        return true;

}


boolean_t file_checkStat(char *filename, char *description, int permmask) {
        ASSERT(filename);
        ASSERT(description);

        errno = 0;
        struct stat buf;
        if (stat(filename, &buf) < 0) {
                LogError("Cannot stat the %s '%s' -- %s\n", description, filename, STRERROR);
                return false;
        }
        if (! S_ISREG(buf.st_mode)) {
                LogError("The %s '%s' is not a regular file.\n", description,  filename);
                return false;
        }
        if (buf.st_uid != geteuid())  {
                LogError("The %s '%s' must be owned by you.\n", description, filename);
                return false;
        }
        if ((buf.st_mode & 0777) & ~permmask) {
                LogError("The %s '%s' permission 0%o is wrong, maximum 0%o allowed\n", description, filename, buf.st_mode & 0777, permmask & 0777);
                return false;
        }

        return true;

}


boolean_t file_checkQueueDirectory(char *path) {
        struct stat st;

        if (stat(path, &st)) {
                if (errno == ENOENT) {
                        if (mkdir(path, 0700)) {
                                LogError("Cannot create the event queue directory %s -- %s\n", path, STRERROR);
                                return false;
                        }
                } else {
                        LogError("Cannot read the event queue directory %s -- %s\n", path, STRERROR);
                        return false;
                }
        } else if (! S_ISDIR(st.st_mode)) {
                LogError("Event queue: the %s is not directory\n", path);
                return false;
        }
        return true;
}


boolean_t file_checkQueueLimit(char *path, int limit) {
        if (limit < 0)
                return true;
        DIR *dir = opendir(path);
        if (! dir) {
                LogError("Cannot open the event queue directory %s -- %s\n", path, STRERROR);
                return false;
        }
        int used = 0;
        struct dirent *de = NULL;
        while ((de = readdir(dir)) ) {
                char buf[PATH_MAX];
                snprintf(buf, sizeof(buf), "%s/%s", path, de->d_name);
                if (File_isFile(buf) && ++used > limit) {
                        LogError("Event queue is full\n");
                        closedir(dir);
                        return false;
                }
        }
        closedir(dir);
        return true;
}


boolean_t file_writeQueue(FILE *file, void *data, size_t size) {
        size_t rv;

        ASSERT(file);

        /* write size */
        if ((rv = fwrite(&size, 1, sizeof(size_t), file)) != sizeof(size_t)) {
                if (feof(file) || ferror(file))
                        LogError("Queued event file: unable to write event size -- %s\n", feof(file) ? "end of file" : "stream error");
                else
                        LogError("Queued event file: unable to write event size -- read returned %lu bytes\n", (unsigned long)rv);
                return false;
        }

        /* write data if any */
        if (size > 0) {
                if ((rv = fwrite(data, 1, size, file)) != size) {
                        if (feof(file) || ferror(file))
                                LogError("Queued event file: unable to write event size -- %s\n", feof(file) ? "end of file" : "stream error");
                        else
                                LogError("Queued event file: unable to write event size -- read returned %lu bytes\n", (unsigned long)rv);
                        return false;
                }
        }

        return true;
}


void *file_readQueue(FILE *file, size_t *size) {
        size_t rv;
        void *data = NULL;

        ASSERT(file);

        /* read size */
        if ((rv = fread(size, 1, sizeof(size_t), file)) != sizeof(size_t)) {
                if (feof(file) || ferror(file))
                        LogError("Queued event file: unable to read event size -- %s\n", feof(file) ? "end of file" : "stream error");
                else
                        LogError("Queued event file: unable to read event size -- read returned %lu bytes\n", (unsigned long)rv);
                return NULL;
        }

        /* read data if any (allow 1MB at maximum to prevent enormous memory allocation) */
        if (*size > 0 && *size < 1048576) {
                data = CALLOC(1, *size);
                if ((rv = fread(data, 1, *size, file)) != *size) {
                        FREE(data);
                        if (feof(file) || ferror(file))
                                LogError("Queued event file: unable to read event data -- %s\n", feof(file) ? "end of file" : "stream error");
                        else
                                LogError("Queued event file: unable to read event data -- read returned %lu bytes\n", (unsigned long)rv);
                        return NULL;
                }
        }
        return data;
}

