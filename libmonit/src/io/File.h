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


#ifndef FILE_INCLUDED
#define FILE_INCLUDED
#include <sys/types.h>


/**
 * A set of low-level class methods for operating on a file.
 * 
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/**
 * The system-dependent filename separator character. On UNIX systems
 * the value of this char is '/' on Win32 systems it is '\'.
 */
extern const char SEPARATOR_CHAR;

/**
 * The separator character, provided as a string for convenience. This
 * string contains a single character, namely SEPARATOR_CHAR.
 */
extern const char *SEPARATOR;

/**
 * The system-dependent path-separator character. This character is
 * used to separate filenames in a sequence of files given as a path
 * list. On UNIX systems, this character is ':' on Win32 systems it is ';'.
 */
extern const char PATH_SEPARATOR_CHAR;

/**
 * The system-dependent path-separator character, provided as a string
 * for convenience. This string contains a single character, namely
 * PATH_SEPARATOR_CHAR.
 */
extern const char *PATH_SEPARATOR;


/**
 * Open <code>file</code> and return its file descriptor. The file is 
 * opened in non-blocking mode, meaning that read and write operations
 * will not block. Clients can pass the descriptor to an Input- and/or 
 * an OutputStream for reading/writing to the file. The mode parameter
 * is used to specify the access requested for the file. The mode may 
 * be one of
 * <ol>
 * <li>"r" Open for reading. The stream is positioned at the beginning 
 * of the file</li>
 * <li>"w" Open for writing. If the file does not exist it will be
 * created, if it exist it is truncated to length 0. The stream is 
 * positioned at the beginning of the file</li>
 * <li>"r+" Open for reading and writing. The stream is positioned 
 * at the beginning of the file</li>
 * <li>"w+" Open for reading and writing. If the file does not exist it 
 * will be created, if it exist it is truncated to length 0. The stream is 
 * positioned at the beginning of the file</li>
 * <li>"a" Open for writing at the end of the file (appending). If the
 * file does not exist it will be created. The stream is positioned at
 * the end of the file</li>
 * <li>"a+" Open for reading and writing. If the file does not exist it 
 * will be created. The stream is positioned at the end of the file</li>
 *</ol>
 * @param file An absolute  file path
 * @param mode the file access mode
 * @return A file descriptor or -1 if the file cannot be opened. Use 
 * System_getLastError() to get a description of the error that occurred
 */
int File_open(const char *file, const char *mode);


/**
 * Close the file descriptor <code>fd</code>
 * @param fd An open file descriptor
 * @return true on success or false if an error occurred.
 */
int File_close(int fd);


/**
 * Move the <code>read</code> position in the file to the beginning
 * of input.
 * @param fd An open file descriptor
 * @return true if success otherwise false and errno is set accordingly
 */
int File_rewind(int fd);


/**
 * Returns the last modified time stamp for the given <code>file</code>. 
 * A file's mtime is changed by a file write operation
 * @param file An absolute file path
 * @return the last modified time stamp or -1 if the file was not found.
 */
time_t File_mtime(const char *file);


/**
 * Returns the time when the <code>file</code> status was last changed. 
 * A file ctime is changed by a file write, chmod, chown, rename, etc.
 * @param file An absolute file path
 * @return the last changed time stamp or -1 if the file was not found 
 */
time_t File_ctime(const char *file);


/**
 * Returns the time when <code>file</code> data was last accessed. 
 * A file atime is changed by a file read operation
 * @param file An absolute file path
 * @return the last accessed time stamp or -1 if the file was not found.
 */
time_t File_atime(const char *file);


/**
 * Check if this is a regular <code>file</code>.
 * @param file An absolute file path
 * @return true if file exist and is a regular file, otherwise false
 */
int File_isFile(const char *file);


/**
 * Returns true if <code>file</code> is a Unix Domain socket
 * @param file An absolute file path
 * @return true if file is a socket file, otherwise false
 */
int File_isSocket(const char *file);

        
/**
 * Check if <code>file</code> is a directory
 * @param file An absolute file path
 * @return true if file exist and is a directory, otherwise false
 */
int File_isDirectory(const char *file);


/**
 * Check if the <code>file</code> exist
 * @param file An absolute file path
 * @return true if file exist otherwise false
 */
int File_exist(const char *file);


/**
 * Returns the file type. The returned char is one of
 * <ul>
 * <li>r - regular file</li>
 * <li>d - directory</li>
 * <li>c - char special</li>
 * <li>b - block special</li>
 * <li>l - symbolic link</li>
 * <li>p - fifo or socket</li>
 * <li>s - socket</li>
 * <li>? - file does not exist</li>
 * </ul>
 * @param file An absolute file path
 * @return The file type
 */
char File_type(const char *file);


/**
 * Returns the <code>file</code> size in bytes
 * @param file An absolute file path
 * @return The file size or -1 if it does not exist
 */
off_t File_size(const char *file);


/**
 * Changes permission bits on the <code>file</code> to the bit pattern 
 * represented by <code>perm</code>. On POSIX systems, see chmod(1) for 
 * details. Example, <code>File_chmod(file, 0644);</code> sets read and 
 * write permission for the File owner and read-only permission for others.
 * @param file An absolute file path
 * @param perm An octal number specifying a permission bit pattern.
 * @return true if success otherwise false if for instance the File does
 * not exist in the file system.
 */
int File_chmod(const char *file, mode_t perm);


/**
 * Returns the permission bit pattern for the <code>file</code>. See also
 * File_chmod().
 * @param file An absolute file path
 * @return An octal number specifying the permission set for this file
 * or -1 if the file does not exist 
 */
mode_t File_mod(const char *file);


/**
 * Returns the current umask value for this process. Umask values are 
 * subtracted from the default permissions. Files and directories 
 * are created with default permission set to 0666 and 0777 respectively.
 * 
 * Simply put, the umask value is a set of permission bits to turn back off 
 * a file creation mode. When a file or directory is created, the permission
 * bits specified are <i>anded</i> with the complement of the umask value to
 * determine the actual bits that will be set. For instance, when a file is 
 * created with File_open() the permission for the new file is set 
 * according to
 * <pre>
 * 0666 & ~File_umask(). If File_umask() is 022 then; 0666 & ~022 = 0644
 * </pre>
 * If a new directory is created with Dir_mkdir() then permission is set
 * according to,
 * <pre>
 * 0777 & ~File_umask(). If File_umask() is 022 then; 0777 & ~022 = 0755
 * </pre>
 * Here is a ruby on-liner to play with, to see how umask modifies default
 * permissions
 * <pre>
 * ruby -e 'printf("%#o\n", (0666 & ~0022))' 
 * </pre>
 * See also http://en.wikipedia.org/wiki/Umask and umask(2) on Unix
 * @return An octal number representing the umask value for this process
 */
mode_t File_umask(void);


/**
 * Set the umask value for this process. The default value is 022, unless
 * changed by the user. See also File_umask()
 * @param mask The new umask value, as a 3 digit octal number, e.g. 007
 * @return The old umask value for this process
 */
mode_t File_setUmask(mode_t mask);


/**
 * Check if the <code>file</code> is readable for the real user id (uid) of 
 * this process
 * @param file An absolute path
 * @return true if the file is readable, otherwise false
 */
int File_isReadable(const char *file);


/**
 * Check if the <code>file</code> is writable for the real user id (uid) of 
 * this process
 * @param file An absolute path
 * @return true if the file is writable, otherwise false
 */
int File_isWritable(const char *file);


/**
 * Check if the <code>file</code> is executable for the real user id (uid) of 
 * this process
 * @param file An absolute path
 * @return true if the file is executable, otherwise false
 */
int File_isExecutable(const char *file);


/**
 * Delete <code>file</code> from the filesystem
 * @param file An absolute path
 * @return true if success otherwise false
 */
int File_delete(const char *file);


/**
 * Renames the given <code>file</code> to the new <code>name</code>
 * Both <code>file</code> and <code>name</code> should contain a full path.
 * @param file The name of the file to be renamed
 * @param name The new name for the file. 
 * @return true if success otherwise false
 */
int File_rename(const char *file, const char *name);


/**
 * Returns only the filename with leading directory components
 * removed. This function does not modify the path string.
 * @param path A file path string
 * @return A pointer to the base name in path
 */
const char *File_basename(const char *path);


/**
 * Strip the filename and return only the path, including the last path
 * separator. The path parameter is modified so if you need to preserve 
 * the path string, copy the string before it is passed to this function. 
 * If no file separator can be found in the given path the following string
 * is returned "." meaning the current directory.
 * @param path A file path string
 * @return The dir name from the path
 */
char *File_dirname(char *path);


/**
 * Returns only the file extension from the <code>path</code>. This
 * function does not modify the path string. For instance given
 * the file path: <code>zild/webapps/ROOT/hello.html</code> this method 
 * returns a pointer to the sub-string <code>html</code>. If the 
 * <code>path</code> string does not contain an extension this 
 * method returns NULL.
 * @param path A file path string
 * @return A pointer to the file extension in the <code>path</code>
 * string or NULL if no extension is found.
 */
const char *File_extension(const char *path);


/**
 * If path is a directory, remove the last SEPARATOR char if any.
 * Example:
 * <pre>
 * File_removeTrailingSeparator("/tmp/")    -> "/tmp"
 * File_removeTrailingSeparator("/tmp")     -> "/tmp"
 * File_removeTrailingSeparator(".monitrc") -> ".monitrc"
 * </pre>
 * @param path A file path string
 * @return A pointer to the path string
 */
char *File_removeTrailingSeparator(char *path);


/**
 * Returns the canonicalized absolute pathname of the <code>path</code>
 * parameter. The <code>resolved</code> buffer must have size equal to
 * PATH_MAX
 * @param path The file path to normalize
 * @param resolved The buffer to write the real path too
 * @return A pointer to the resolved buffer or NULL if an error occured
 */
char *File_getRealPath(const char *path, char *resolved);


#endif
