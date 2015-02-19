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


#ifndef MONIT_FILE_H
#define MONIT_FILE_H


/**
 *  Utilities used for managing files used by monit.
 *
 *  @file
 */


/**
 * Initialize the programs file variables
 */
void file_init();


/**
 * Finalize and remove temporary files
 */
void file_finalize();


/**
 * Get a object's last modified timestamp.
 * @param object A object to stat
 * @param type Requested object's type
 * @return Max of either st_mtime or st_ctime or
 * 0 if not found or different type of object
 */
time_t file_getTimestamp(char *object, mode_t type);


/**
 * Search the system for the monit control file. Try first ~/.monitrc,
 * if that fails try /etc/monitrc, then /usr/local/etc/monitrc and
 * finally ./monitrc.  Exit the application if the control file was
 * not found.
 * @return The location of monits control file (monitrc)
 */
char *file_findControlFile();


/**
 * Create a program's pidfile - Such a file is created when in daemon
 * mode.
 * @param pidfile The name of the pidfile to create
 * @return true if the file was created, otherwise false.
 */
boolean_t file_createPidFile(char *pidfile);


/**
 * Security check for files. The files must have the same uid as the
 * REAL uid of this process, it must have permissions no greater than
 * "maxpermission" and it must not be a symbolic link.  We check these
 * conditions here.
 * @param filename The filename of the checked file
 * @param description The description of the checked file
 * @param permmask The permission mask for the file
 * @return true if the test succeeded otherwise false
 */
boolean_t file_checkStat(char *filename, char *description, int permmask);


/**
 * Check whether the specified directory exist or create it using
 * specified mode.
 * @param path The fully qualified path to the directory
 * @return true if the succeeded otherwise false
 */
boolean_t file_checkQueueDirectory(char *path);


/**
 * Check the queue size limit.
 * @param path The fully qualified path to the directory
 * @param mode The queue limit
 * @return true if the succeeded otherwise false
 */
boolean_t file_checkQueueLimit(char *path, int limit);


/**
 * Write data to the queue file
 * @param file Filedescriptor to write to
 * @param data Data to be written
 * @param size Size of the data to be written
 * @return true if the succeeded otherwise false
 */
boolean_t file_writeQueue(FILE *file, void *data, size_t size);


/**
 * Read the data from the queue file's actual position
 * @param file Filedescriptor to read from
 * @param size Size of the data read
 * @return The data read if any or NULL. The size parameter is set
 * appropriately.
 */
void *file_readQueue(FILE *file, size_t *size);


#endif
