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
  if(Run.pidfile == NULL) {
    /* Set the location of this programs pidfile */
    if(! getuid()) {
      snprintf(pidfile, STRLEN, "%s/%s", MYPIDDIR, MYPIDFILE);
    } else {
      snprintf(pidfile, STRLEN, "%s/.%s", Run.Env.home, MYPIDFILE);
    }
    Run.pidfile = Str_dup(pidfile);
  }

  /* Set the location of monit's id file */
  if(Run.idfile == NULL) {
    snprintf(buf, STRLEN, "%s/.%s", Run.Env.home, MYIDFILE);
    Run.idfile = Str_dup(buf);
  }
  Util_monitId(Run.idfile);

  /* Set the location of monit's state file */
  if(Run.statefile == NULL) {
    snprintf(buf, STRLEN, "%s/.%s", Run.Env.home, MYSTATEFILE);
    Run.statefile = Str_dup(buf);
  }

}


void file_finalize() {
  unlink(Run.pidfile);
}


time_t file_getTimestamp(char *object, mode_t type) {

  struct stat buf;

  ASSERT(object);

  if(! stat(object, &buf)) {
    if(((type == S_IFREG) && S_ISREG(buf.st_mode)) ||
       ((type == S_IFDIR) && S_ISDIR(buf.st_mode)) ||
       ((type == S_IFSOCK) && S_ISSOCK(buf.st_mode)) ||
       ((type == (S_IFREG|S_IFDIR)) && (S_ISREG(buf.st_mode) || S_ISDIR(buf.st_mode)))
       ) {
      return MAX(buf.st_mtime, buf.st_ctime);
    } else {
      LogError("Invalid object type - %s\n", object);
    }
  }

  return FALSE;

}


char *file_findControlFile() {

  char *rcfile = CALLOC(sizeof(char), STRLEN + 1);

  snprintf(rcfile, STRLEN, "%s/.%s", Run.Env.home, MONITRC);
  if(file_exist(rcfile)) {
    return rcfile;
  }
  snprintf(rcfile, STRLEN, "/etc/%s", MONITRC);
  if(file_exist(rcfile)) {
    return rcfile;
  }
  snprintf(rcfile, STRLEN, "%s/%s", SYSCONFDIR, MONITRC);
  if(file_exist(rcfile)) {
    return rcfile;
  }
  snprintf(rcfile, STRLEN, "/usr/local/etc/%s", MONITRC);
  if(file_exist(rcfile)) {
    return rcfile;
  }
  if(file_exist(MONITRC)) {
    snprintf(rcfile, STRLEN, "%s/%s", Run.Env.cwd, MONITRC);
    return rcfile;
  }
  LogError("Cannot find the control file at ~/.%s, /etc/%s, %s/%s, /usr/local/etc/%s or at ./%s \n", MONITRC, MONITRC, SYSCONFDIR, MONITRC, MONITRC, MONITRC);
  exit(1);

}


int file_createPidFile(char *pidfile) {
  ASSERT(pidfile);

  unlink(pidfile);
  FILE *F = fopen(pidfile, "w");
  if (! F) {
    LogError("Error opening pidfile '%s' for writing -- %s\n", pidfile, STRERROR);
    return(FALSE);
  }
  fprintf(F, "%d\n", (int)getpid());
  fclose(F);

  return TRUE;

}


int file_isFile(char *file) {

  struct stat buf;

  ASSERT(file);

  return (stat(file, &buf) == 0 && S_ISREG(buf.st_mode));

}


int file_isDirectory(char *dir) {

        struct stat buf;

  ASSERT(dir);

  return (stat(dir, &buf) == 0 && S_ISDIR(buf.st_mode));

}


int file_isFifo(char *fifo) {

  struct stat buf;

  ASSERT(fifo);

  return (stat(fifo, &buf) == 0 && S_ISFIFO(buf.st_mode));

}


int file_exist(char *file) {

  struct stat buf;

  ASSERT(file);

  return (stat(file, &buf) == 0);

}


int file_checkStat(char *filename, char *description, int permmask) {
  struct stat buf;
  errno = 0;

  ASSERT(filename);
  ASSERT(description);

  if(stat(filename, &buf) < 0) {
    LogError("Cannot stat the %s '%s' -- %s\n", description, filename, STRERROR);
    return FALSE;
  }
  if(!S_ISREG(buf.st_mode)) {
    LogError("The %s '%s' is not a regular file.\n", description,  filename);
    return FALSE;
  }
  if(buf.st_uid != geteuid())  {
    LogError("The %s '%s' must be owned by you.\n", description, filename);
    return FALSE;
  }
  if((buf.st_mode & 0777 ) & ~permmask) {
    /*
       Explanation:

           buf.st_mode & 0777 ->  We just want to check the
                                  permissions not the file type...
                                  we did it already!
           () & ~permmask ->      We check if there are any other
                                  permissions set than in permmask
    */
    LogError("The %s '%s' must have permissions no more than -%c%c%c%c%c%c%c%c%c (0%o); right now permissions are -%c%c%c%c%c%c%c%c%c (0%o).\n",
        description, filename,
        permmask&S_IRUSR?'r':'-',
        permmask&S_IWUSR?'w':'-',
        permmask&S_IXUSR?'x':'-',
        permmask&S_IRGRP?'r':'-',
        permmask&S_IWGRP?'w':'-',
        permmask&S_IXGRP?'x':'-',
        permmask&S_IROTH?'r':'-',
        permmask&S_IWOTH?'w':'-',
        permmask&S_IXOTH?'x':'-',
        permmask&0777,
        buf.st_mode&S_IRUSR?'r':'-',
        buf.st_mode&S_IWUSR?'w':'-',
        buf.st_mode&S_IXUSR?'x':'-',
        buf.st_mode&S_IRGRP?'r':'-',
        buf.st_mode&S_IWGRP?'w':'-',
        buf.st_mode&S_IXGRP?'x':'-',
        buf.st_mode&S_IROTH?'r':'-',
        buf.st_mode&S_IWOTH?'w':'-',
        buf.st_mode&S_IXOTH?'x':'-',
        buf.st_mode& 0777);
    return FALSE;
  }

  return TRUE;

}


int file_checkQueueDirectory(char *path) {
  struct stat st;

  if(stat(path, &st)) {
    if(errno == ENOENT) {
      if(mkdir(path, 0700)) {
        LogError("Cannot create the event queue directory %s -- %s\n", path, STRERROR);
        return FALSE;
      }
    } else {
      LogError("Cannot read the event queue directory %s -- %s\n", path, STRERROR);
      return FALSE;
    }
  } else if(! S_ISDIR(st.st_mode)) {
    LogError("Event queue: the %s is not directory\n", path);
    return FALSE;
  }
  return TRUE;
}


int file_checkQueueLimit(char *path, int limit) {
  int            used = 0;
  DIR           *dir = NULL;
  struct dirent *de = NULL;

  if(limit < 0)
    return TRUE;

  if(! (dir = opendir(path)) ) {
    LogError("Cannot open the event queue directory %s -- %s\n", path, STRERROR);
    return FALSE;
  }
  while( (de = readdir(dir)) ) {
    struct stat st;

    if(!stat(de->d_name, &st) && S_ISREG(st.st_mode) && ++used > limit) {
      LogError("Event queue is full\n");
      closedir(dir);
      return FALSE;
    }
  }
  closedir(dir);
  return TRUE;
}


int file_writeQueue(FILE *file, void *data, size_t size) {
  size_t rv;

  ASSERT(file);

  /* write size */
  if((rv = fwrite(&size, 1, sizeof(size_t), file)) != sizeof(size_t)) {
    if (feof(file) || ferror(file))
      LogError("Queued event file: unable to write event size -- %s\n", feof(file) ? "end of file" : "stream error");
    else
      LogError("Queued event file: unable to write event size -- read returned %lu bytes\n", (unsigned long)rv);
    return FALSE;
  }

  /* write data if any */
  if(size > 0) {
    if((rv = fwrite(data, 1, size, file)) != size) {
      if (feof(file) || ferror(file))
        LogError("Queued event file: unable to write event size -- %s\n", feof(file) ? "end of file" : "stream error");
      else
        LogError("Queued event file: unable to write event size -- read returned %lu bytes\n", (unsigned long)rv);
      return FALSE;
    }
  }

  return TRUE;
}


void *file_readQueue(FILE *file, size_t *size) {
  size_t rv;
  void *data = NULL;

  ASSERT(file);

  /* read size */
  if((rv = fread(size, 1, sizeof(size_t), file)) != sizeof(size_t)) {
    if (feof(file) || ferror(file))
      LogError("Queued event file: unable to read event size -- %s\n", feof(file) ? "end of file" : "stream error");
    else
      LogError("Queued event file: unable to read event size -- read returned %lu bytes\n", (unsigned long)rv);
    return NULL;
  }

  /* read data if any (allow 1MB at maximum to prevent enormous memory allocation) */
  if(*size > 0 && *size < 1048576) {
    data = CALLOC(1, *size);
    if((rv = fread(data, 1, *size, file)) != *size) {
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

