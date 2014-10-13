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


#ifndef PROCESS_INCLUDED
#define PROCESS_INCLUDED
#include <sys/types.h>
#include "io/InputStream.h"
#include "io/OutputStream.h"

/**
 * A <b>Process</b> represent an operating system process. A new Process 
 * object is created via Command_execute(). 
 * 
 * The sub-process represented by this Process does not have its own terminal 
 * or console. All its standard I/O (i.e. stdin, stdout, stderr) operations 
 * will be redirected to the parent process where they can be accessed using 
 * the streams obtained using the methods Process_getOutputStream(), 
 * Process_getInputStream(), and Process_getErrorStream(). Your program can 
 * then use these streams to feed input to and get output from the sub-process.
 * 
 * The sub-process continues executing until it stops or until either 
 * Process_free() is called or it is terminated with either Process_terminate()
 * or Process_kill().
 *
 * <h4>Environment</h4>
 * The Process inherits the environment from the calling process. Clients can
 * also call Command_setEnv() to set or reset environment variables as needed
 * <em>before</em> calling Command_execute(). Environment variables set this way
 * will be added to the sub-process at execution time.
 *
 * @see Command.h
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


#define T Process_T
typedef struct T *T;


/**
 * Destroy a Process object and free allocated resources. Clients
 * should call this method when they are done with the Process object.
 * This method will kill the sub-process represented by this Process
 * object if it is still running and close down stdio to the sub-process.
 * @param P a Process object reference
 */
void Process_free(T *P);


/** @name Properties */
//@{

/**
 * Returns the user id of the sub-process
 * @param P A Process object
 * @return The user id of the sub-process
 */
uid_t Process_getUid(T P);


/**
 * Returns the group id of the sub-process
 * @param P A Process object
 * @return The group id of the sub-process
 */
gid_t Process_getGid(T P);


/**
 * Returns the Process timeout. 
 * @param P A Process object
 * @return The number of seconds this Process has until exit before
 * the <code>onTimeout</code> handler is called if it is defined for
 * the Command. 0 means that there is no timeout.
 */
int Process_getTimeout(T P);


/**
 * Returns the working directory of the Process
 * @param P A Process object
 * @return The Process working directory
 */
const char *Process_getDir(T P);


/**
 * Returns the Process's identification number
 * @param P A Process object
 * @return The process identification number of the sub-process
 */
pid_t Process_getPid(T P);


/**
 * Causes the current thread to wait, if necessary, until the sub-process
 * represented by this Process object has terminated. This method returns
 * immediately if the sub-process has already terminated. If the sub-process
 * has not yet terminated, the calling thread will be blocked until the 
 * sub-process exits. By convention, the value 0 indicates normal termination.
 * @param P A Process object
 * @return The exit status of the sub-process or -1 if an error occur. 
 * Investigate errno for a description of the error
 */
int Process_waitFor(T P);


/**
 * Returns the Process exit status. If the sub-process is still running, this 
 * method returns -1, otherwise the sub-process exit status. By convention, 
 * the value 0 indicates normal termination. 
 * @param P A Process object
 * @return The exit status of the sub-process or -1 if the sub-process is still
 * running.
 */
int Process_exitStatus(T P);


/**
 * Returns true if the sub-process is running otherwise false
 * @param P A Process object
 * @return True if Process is running otherwise false
 */
int Process_isRunning(T P);


/**
 * Returns the output stream connected to the normal input of the sub-process. 
 * Output to the stream is piped into the standard input of the process 
 * represented by this Process object. 
 * @param P A Process object
 * @return The output stream connected to the normal input of the sub-process.
 */
OutputStream_T Process_getOutputStream(T P);


/**
 * Returns the input stream connected to the normal output of the sub-process. 
 * The stream obtains data piped from the standard output of the process 
 * represented by this Process object.
 * @param P A Process object
 * @return The input stream connected to the normal output of the sub-process.
 */
InputStream_T Process_getInputStream(T P);


/**
 * Returns the input stream connected to the error output of the sub-process. 
 * The stream obtains data piped from the error output of the process 
 * represented by this Process object. 
 * @param P A Process object
 * @return The input stream connected to the error output of the sub-process.
 */
InputStream_T Process_getErrorStream(T P);


//@}


/**
 * Destroy the sub-process. The sub-process is destroyed by sending
 * it a termination signal (SIGTERM)
 * @param P A Process object
 */
void Process_terminate(T P);


/**
 * Kill the sub-process. The sub-process is destroyed by sending
 * it a termination signal (SIGKILL). While SIGTERM may be blocked
 * by a process, SIGKILL can not be blocked and will kill the process
 * @param P A Process object
 */
void Process_kill(T P);


#undef T
#endif

