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


#ifndef DIR_INCLUDED
#define DIR_INCLUDED


/**
 * A collection of class methods for operating on a dir
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/** @name class methods */
//@{


/**
 * Creates the directory named by this absolute pathname. The optional 
 * <code>perm</code> parameter specify the permission for the created
 * directory. If perm is 0 the directory is created with standard 
 * permission as modified by the process umask.
 * @param dir An absolute directory path
 * @param perm An octal number specifying a permission bit pattern, e.g. 0775
 * or 0 for the default.
 * @return true if success otherwise false, System_getLastError() can be
 * used to get a description of the error that occurred
 * @see File_umask()
 */
int Dir_mkdir(const char *dir, int perm);


/**
 * Delete the directory named by this absolute pathname. This method
 * fails if the directory <code>dir</code> is not empty.
 * @param dir An absolute  directory path
 * @return true if success otherwise false and System_getLastError() can be
 * used to get a description of the error that occurred
 */
int Dir_delete(const char *dir);


/**
 * Changes the current working directory of the process to the given 
 * <code>path</code>.
 * @param path An absolute directory path
 * @return true if success otherwise false and System_getLastError() can be
 * used to get a description of the error that occurred
 */
int Dir_chdir(const char *path);


/**
 * Returns the current working directory of the process.
 * @param result A buffer to write the result to. 
 * @param length The length of the result buffer
 * @return A pointer to the result buffer or NULL in case of error
 */
const char *Dir_cwd(char *result, int length);

//@}

#endif
