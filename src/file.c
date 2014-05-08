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


/**
 * Initialize the programs file variables
 */
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


/**
 * Finalize and remove temporary files and make sure Monit id file exist
 */
void file_finalize() {
  unlink(Run.pidfile);
  // Make sure that Monit id file exist
  if (! file_exist(Run.idfile)) {
    FILE *f =  fopen(Run.idfile,"w");
    if (! f) {
      LogError("Error opening Monit id file '%s' for writing -- %s\n", Run.idfile, STRERROR);
    } else {
      fprintf(f, "%s\n", Run.id);
      fclose(f);
    }
  }
}


/**
 * Get a object's last modified timestamp.
 * @param object A object to stat
 * @param type Requested object's type
 * @return Max of either st_mtime or st_ctime or
 * FALSE if not found or different type of object
 */
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


/**
 * Search the system for the monit control file. Try first ~/.monitrc,
 * if that fails try /etc/monitrc, then SYSCONFDIR/monitrc (default:
 * /usr/local/etc/monitrc) and finally ./monitrc.
 * Exit the application if the control file was not found.
 * @return The location of monits control file (monitrc)
 */
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


/**
 * Create a program's pidfile - Such a file is created when in daemon
 * mode. The file is created with mask = MYPIDMASK (usually 644).
 * @param pidfile The name of the pidfile to create
 * @return TRUE if the file was created, otherwise FALSE.
 */
int file_createPidFile(char *pidfile) {

  FILE *F = NULL;

  ASSERT(pidfile);

  umask(MYPIDMASK);
  unlink(pidfile);
  if ((F = fopen(pidfile,"w")) == (FILE *)NULL) {
    LogError("Error opening pidfile '%s' for writing -- %s\n", pidfile, STRERROR);
    return(FALSE);
  }
  fprintf(F, "%d\n", (int)getpid());
  fclose(F);

  return TRUE;

}


/**
 * Check if the file is a regular file
 * @param file A path to the file to check
 * @return TRUE if file exist and is a regular file, otherwise FALSE
 */
int file_isFile(char *file) {

  struct stat buf;

  ASSERT(file);

  return (stat(file, &buf) == 0 && S_ISREG(buf.st_mode));

}


/**
 * Check if this is a directory.
 * @param dir An absolute  directory path
 * @return TRUE if dir exist and is a regular directory, otherwise
 * FALSE
 */
int file_isDirectory(char *dir) {

        struct stat buf;

  ASSERT(dir);

  return (stat(dir, &buf) == 0 && S_ISDIR(buf.st_mode));

}


/**
 * Check if this is a fifo
 * @param fifo A path to the fifo to check
 * @return TRUE if fifo exist, otherwise FALSE
 */
int file_isFifo(char *fifo) {

  struct stat buf;

  ASSERT(fifo);

  return (stat(fifo, &buf) == 0 && S_ISFIFO(buf.st_mode));

}


/**
 * Check if the file exist on the system
 * @file A path to the file to check
 * @return TRUE if file exist otherwise FALSE
 */
int file_exist(char *file) {

  struct stat buf;

  ASSERT(file);

  return (stat(file, &buf) == 0);

}


/**
 * Security check for files. The files must have the same uid as the
 * REAL uid of this process, it must have permissions no greater than
 * "maxpermission".
 * @param filename The filename of the checked file
 * @param description The description of the checked file
 * @param permmask The permission mask for the file
 * @return TRUE if the test succeeded otherwise FALSE
 */
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


/**
 * Check whether the specified directory exist or create it using
 * specified mode.
 * @param path The fully qualified path to the directory
 * @param mode The permission for the directory
 * @return TRUE if the succeeded otherwise FALSE
 */
int file_checkQueueDirectory(char *path, mode_t mode) {
  struct stat st;

  if(stat(path, &st)) {
    if(errno == ENOENT) {
      int rv;
      mode_t mask = umask(QUEUEMASK);
      rv = mkdir(path, mode);
      umask(mask);
      if(rv) {
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


/**
 * Check the queue size limit.
 * @param path The fully qualified path to the directory
 * @param limit The queue limit
 * @return TRUE if the succeeded otherwise FALSE
 */
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


/**
 * Write data to the queue file
 * @param file Filedescriptor to write to
 * @param data Data to be written
 * @param size Size of the data to be written
 * @return TRUE if the succeeded otherwise FALSE
 */
int file_writeQueue(FILE *file, void *data, size_t size) {
  size_t rv;

  ASSERT(file);

  /* write size */
  if((rv = fwrite(&size, 1, sizeof(size_t), file)) != sizeof(size_t)) {
    if (feof(file) || ferror(file))
      LogError("Queued event file: unable to write event size -- %s\n", feof(file) ? "end of file" : "stream error");
    else
      LogError("Queued event file: unable to write event size -- read returned %d bytes\n", rv);
    return FALSE;
  }

  /* write data if any */
  if(size > 0) {
    if((rv = fwrite(data, 1, size, file)) != size) {
      if (feof(file) || ferror(file))
        LogError("Queued event file: unable to write event size -- %s\n", feof(file) ? "end of file" : "stream error");
      else
        LogError("Queued event file: unable to write event size -- read returned %d bytes\n", rv);
      return FALSE;
    }
  }

  return TRUE;
}


/**
 * Read the data from the queue file's actual position
 * @param file Filedescriptor to read from
 * @param size Size of the data read
 * @return The data read if any or NULL. The size parameter is set
 * appropriately.
 */
void *file_readQueue(FILE *file, size_t *size) {
  size_t rv;
  void *data = NULL;

  ASSERT(file);

  /* read size */
  if((rv = fread(size, 1, sizeof(size_t), file)) != sizeof(size_t)) {
    if (feof(file) || ferror(file))
      LogError("Queued event file: unable to read event size -- %s\n", feof(file) ? "end of file" : "stream error");
    else
      LogError("Queued event file: unable to read event size -- read returned %d bytes\n", rv);
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
        LogError("Queued event file: unable to read event data -- read returned %d bytes\n", rv);
      return NULL;
    }
  }
  return data;
}

