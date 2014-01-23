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
#include <unistd.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <dirent.h>
#include <glob.h>

#include "system/System.h"
#include "Str.h"
#include "File.h"
#include "Dir.h"


/**
 * Implementation of the Dir interface
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ----------------------------------------------------------- Definitions */



/* ---------------------------------------------------------------- Public */



/* ----------------------------------------------------------------- Class */


int Dir_mkdir(const char *dir, int perm) {
        if (dir) {
                if (mkdir(dir, 0777) == 0) {
                        if (perm != 0)
                                File_chmod(dir, perm);
                        return true;
                }
        }
        errno = EINVAL;
        return false;
}


int Dir_delete(const char *dir) {
        if (dir)
                return File_delete(dir);
        errno = EINVAL;
        return false;        
}


int Dir_chdir(const char *path) {
        if (path) 
                return (chdir(path)==0);
        errno = EINVAL;
        return false;
}


const char *Dir_cwd(char *result, int length) {
        if (result) 
                return getcwd(result, length);
        errno = EINVAL;
        return result;
}
