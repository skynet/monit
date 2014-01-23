/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
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


#include "Config.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include "Str.h"
#include "system/System.h"
#include "File.h"


/**
 * Implementation of the File Facade for Unix systems. 
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ----------------------------------------------------------- Definitions */


#define DEFAULT_PERM 0666

#define RETURN_FILETYPE(X) do { \
        switch ((X) & S_IFMT) { \
        case S_IFREG:  return 'r'; \
        case S_IFDIR:  return 'd'; \
        case S_IFCHR:  return 'c'; \
        case S_IFBLK:  return 'b'; \
        case S_IFLNK:  return 'l'; \
        case S_IFIFO:  return 'p'; \
        case S_IFSOCK: return 's'; \
        default:       return '?'; \
} } while (0)

const char SEPARATOR_CHAR = '/';
const char *SEPARATOR = "/";
const char PATH_SEPARATOR_CHAR = ':';
const char *PATH_SEPARATOR = ":";


/* ---------------------------------------------------------------- Public */



int File_open(const char *file, const char *mode) {
        if (file && mode) {
                switch(mode[0]) {
                        case 'r':
                                switch (mode[1]) {
                                        case '+': return open(file, O_RDWR|O_NONBLOCK);
                                        default:  return open(file, O_RDONLY|O_NONBLOCK);
                                }
                        case 'w':  
                                switch (mode[1]) {
                                        case '+': return open(file, O_CREAT|O_RDWR|O_TRUNC|O_NONBLOCK, DEFAULT_PERM);
                                        default:  return open(file, O_CREAT|O_WRONLY|O_TRUNC|O_NONBLOCK, DEFAULT_PERM);
                                }
                        case 'a':  
                                switch (mode[1]) {
                                        case '+': return open(file, O_CREAT|O_RDWR|O_APPEND|O_NONBLOCK, DEFAULT_PERM);
                                        default:  return open(file, O_CREAT|O_WRONLY|O_APPEND|O_NONBLOCK, DEFAULT_PERM);
                                }
                }
        }
        errno = EINVAL;
        return -1;
}


int File_close(int fd) {
        int r;
        do
                r = close(fd);
        while (r == -1 && errno == EINTR);
        return (r == 0);
}


int File_rewind(int fd) {
        return (lseek(fd, 0, SEEK_SET) >=0);
}


time_t File_mtime(const char *file) {
        if (file) {
                struct stat buf;
                if (stat(file, &buf) == 0)
                        return buf.st_mtime;
        }
        return -1;
}


time_t File_ctime(const char *file) {
        if (file) {
                struct stat buf;
                if (stat(file, &buf) == 0)
                        return buf.st_ctime;
        }
        return -1;
}


time_t File_atime(const char *file) {
        if (file) {
                struct stat buf;
                if (stat(file, &buf) == 0)
                        return buf.st_atime;
        }
        return -1;
}


int File_isFile(const char *file) {
        if (file) {
                struct stat buf;
                return (stat(file, &buf) == 0 && S_ISREG(buf.st_mode));
        }
        return false;
}


int File_isDirectory(const char *file) {
        if (file) {
                struct stat buf;
                return (stat(file, &buf) == 0 && S_ISDIR(buf.st_mode));
        }
        return false;
}


int File_exist(const char *file) {
        if (file) {
                struct stat buf;
                return (stat(file, &buf) == 0);
        }
        return false;
}


char File_type(const char *file) {
        if (file) {
                struct stat buf;
                if (stat(file, &buf) == 0)
                        RETURN_FILETYPE(buf.st_mode);
        }
        return '?';
}


off_t File_size(const char *file) {
        if (file) {
                struct stat buf;
                if (stat(file, &buf) < 0)
                        return -1;
                return buf.st_size;
        }
        return -1;
}


int File_chmod(const char *file, mode_t mode) {
        if (file)
                return (chmod(file, mode) == 0);
        errno = EINVAL;
        return false;
}


mode_t File_mod(const char *file) {
        if (file) {
                struct stat buf;
                if (stat(file, &buf) == 0)
                        return buf.st_mode;
        }
        return -1;
}


mode_t File_umask(void) {
        mode_t omask = umask(0);
        umask(omask);
        return omask;        
}


mode_t File_setUmask(mode_t mask) {
        mode_t omask = umask(mask);
        return omask;        
}


int File_isReadable(const char *file) {
        if (file) 
                return (access(file, R_OK) == 0);
        return false;
}


int File_isWritable(const char *file) {
        if (file) 
                return (access(file, W_OK) == 0);
        return false;
}


int File_isExecutable(const char *file) {
        if (file) 
                return (access(file, X_OK) == 0);
        return false;
}


int File_delete(const char *file) {
        if (file)
                return (remove(file) == 0);
        errno = ENOENT;
        return false;
}


int File_rename(const char *file, const char *name) {
        if (file)                
                return (rename(file, name) == 0);
        errno = ENOENT;
        return false;
}


const char *File_basename(const char *path) {
        if ((STR_DEF(path))) {
                char *f = strrchr(path, SEPARATOR_CHAR);
                return (f ? ++f : path);
        }
        return path;
}


char *File_dirname(char *path) {
        if ((STR_DEF(path))) {
                char *d = strrchr(path, SEPARATOR_CHAR);
                if (d) 
                        *(d + 1) = 0; /* Keep last separator */
                else {
                        path[0] = '.'; 
                        path[1] = 0;
                }
        }
        return path;
}


const char *File_extension(const char *path) {
        if (STR_DEF(path)) {
                char *e = strrchr(path, '.');
                return (e ? ++e : NULL);
        }
        return NULL;
}


char *File_removeTrailingSeparator(char *path) {
        if (STR_DEF(path)) {
                char *p;
                for (p = path; *p; p++);
                do 
                        *(p--) = 0;
                while ((p > path) && (isspace(*p) || *p == SEPARATOR_CHAR));
        }
        return path;
}


char *File_getRealPath(const char *path, char *resolved) {
        if (path && resolved)
                return realpath(path, resolved);
        return NULL;
}
