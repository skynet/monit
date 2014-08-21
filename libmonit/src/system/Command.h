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


#ifndef COMMAND_INCLUDED
#define COMMAND_INCLUDED
#include "system/Process.h"
#include "util/List.h"


/**
 * A <b>Command</b> creates operating system processes. Each Command instance
 * manages a collection of process attributes. The Command_execute() method
 * creates a new sub-process with those attributes and the method can be invoked
 * repeatedly from the same instance to create new sub-processes with identical
 * or related attributes.
 *
 * Modifying a Command's attributes will affect processes subsequently created,
 * but will never affect previously created processes or the calling process
 * itself.
 *
 * @see Process.h
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


#define T Command_T
typedef struct T *T;


/**
 * Create a new Command object and set the operating system program with
 * arguments to execute. The <code>arg0</code> argument is the first argument
 * in a sequence of arguments to the program. The arguments list can be thought
 * of as arg0, arg1, ..., argn. Together they describe a list of one or more
 * pointers to null-terminated strings that represent the argument list 
 * available to the executed program specified in <code>path</code>. The 
 * list of arguments <em style="color:red">must</em> be terminated by a
 * NULL pointer. Example:
 * <pre>
 * Command_new("/bin/ls", NULL)
 * Command_new("/bin/ls", "-lrt", NULL)
 * Command_new("/bin/sh", "-c", "ps -aef|egrep mmonit", NULL)
 * </pre>
 * @param path A string containing the path to the program to execute
 * @param arg0 The first argument in a sequence of arguments. The last value
 * in the arguments list <strong>must</strong> be NULL.
 * @exception AssertException if the program does not exist or cannot be
 * executed
 * @return This Command object
 */
T Command_new(const char *path, const char *arg0, ...);


/**
 * Destroy A Command object and release allocated resources. Call this
 * method to release a Command object allocated with Command_new()
 * @param C A Command object reference
 */
void Command_free(T *C);


/** @name Properties */
//@{


/**
 * Append an argument to the command that should be used to launch this executable.
 * @param C A Command object
 * @param argument A string argument
 */
void Command_appendArgument(T C, const char *argument);


/**
 * Get arguments count
 * @param C A Command object
 * @return Number of arguments
 */
int Command_getArgumentsCount(T C);


/**
 * Set the user id the sub-process should switch to on exec. If not set, the uid of 
 * the calling process is used. Note that this process must run with super-user
 * privileges for the sub-process to be able to switch uid
 * @param C A Command object
 * @param uid The user id the sub-process should switch to when executed
 */
void Command_setUid(T C, uid_t uid);


/**
 * Returns the uid the sub-process should switch to on exec. 
 * @param C A Command object
 * @return The user id the sub-process should use. Returns 0
 * if not set, meaning the sub-process will run with the same
 * uid as this process.
 */
uid_t Command_getUid(T C);


/**
 * Set the group id the sub-process should switch to on exec. If not set, the gid of 
 * the calling process is used. Note that this process must run with super-user
 * privileges for the sub-process to be able to switch gid
 * @param C A Command object
 * @param gid The group id the sub-process should switch to when executed
 */
void Command_setGid(T C, gid_t gid);


/**
 * Returns the group id the Command should switch to on exec. 
 * @param C A Command object
 * @return The group id the sub-process should use. Returns 0
 * if not set, meaning the sub-process will run with the same
 * gid as this process.
 */
gid_t Command_getGid(T C);


/**
 * Returns the Process timeout. Default is no timeout. The timeout
 * is set with Command_setOnTimeout().
 * @param C A Command object
 * @return The number of seconds to wait before the Process will be
 * destroyed. 0 means that there is no timeout.
 * @see Command_setOnTimeout()
 */
int Command_getTimeout(T C);


/**
 * Set the working directory for the sub-process. If directory cannot be changed
 * the sub-process will exit
 * @param C A Command object
 * @param dir The working directory for the sub-process
 * @exception AssertException if the directory does not exist or is not accessible
 */
void Command_setDir(T C, const char *dir);


/**
 * Returns the working directory for the sub-process. Unless previously
 * set, the returned value is NULL, meaning the calling process's current
 * directory
 * @param C A Command object
 * @return The working directory for the sub-process or NULL meaning the calling
 * process's current directory
 */
const char *Command_getDir(T C);


/**
 * Set or replace the environment variable identified by <code>name</code>.
 * The sub-process initially inherits the environment from the calling process.
 * Environment variables set with this method does not affect the parent 
 * process and only apply to the sub-process.
 * @param C A Command object
 * @param name The environment variable to set or replace
 * @param value The value
 */
void Command_setEnv(T C, const char *name, const char *value);


/**
 * Returns the value of the environment variable identified by 
 * <code>name</code>. 
 * @param C A Command object
 * @param name The environment variable to get the value of
 * @return The value for name or NULL if name was not found
 */
const char *Command_getEnv(T C, const char *name);



/**
 * Returns the operating system program with arguments to be executed by 
 * this Command. The first element in the list is the path to the program
 * and subsequent elements are arguments to the program. Elements in the 
 * list are C-strings. 
 * @param C A Command object
 * @return A list with the operating system program with arguments to 
 * execute. The first element in the list is the program.
 */
List_T Command_getCommand(T C);


//@}


/** 
 * Create a new sub-process using the attributes of this Command object.
 * The new sub-process will execute the command and arguments given in 
 * Command_new(). The caller is responsible for releasing the returned
 * Process_T object by calling Process_free(). If creating the new 
 * sub-process failed, NULL is returned and errno is set to indicate the
 * error. Use e.g. System_getLastError() to get a description of the error
 * that occurred.
 * @param C A Command object
 * @return A new Process_T object representing the sub-process or NULL
 * if execute failed.
 */
Process_T Command_execute(T C);


/** @name Event handlers */
//@{


/**
 * Set the event handler to call on timeout. If the subprocess has not 
 * exited within <code>timeout</code> seconds the <code>onTimeout</code>
 * method is called. The handler is passed a Process object representing
 * the subprocess and an optional application specific pointer.
 * @param C A Command object
 * @param timeout Number of seconds to wait for the subprocess to exit
 * until onTimeout is called
 * @param onTimeout The event handler to call on timeout
 * @param ap An application-specific pointer. If such a pointer is 
 * not needed, just use NULL
 * @exception AssertException if timeout is less than or equal to zero
 * @see Command_getTimeout()
 * @see Process.h
 */
void Command_setOnTimeout(T C, int timeout, void(*onTimeout)(Process_T P, void *ap), void *ap);


//@}


#undef T
#endif

