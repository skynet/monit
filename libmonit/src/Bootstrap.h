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


#ifndef BOOTSTRAP_INCLUDED
#define BOOTSTRAP_INCLUDED



/**
 * Temporary interface for bootstrapping libmonit from Monit.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/**
 * Bootstrap libmonit. This method should be called from Monit at startup
 */
void Bootstrap(void);


/**
 * Set the function to call if a fatal error occurs in the library. In 
 * practice this means Out-Of-Memory errors or uncatched exceptions.
 * Clients may optionally provide this function. If not provided
 * the library will call <code>abort(3)</code> upon encountering a 
 * fatal error. This method provide clients with means to close down 
 * execution gracefully. It is an unchecked runtime error to continue 
 * using the library after the <code>abortHandler</code> was called.
 * @param abortHandler The handler function to call should a fatal 
 * error occur in the library. An explanatory error message is
 * passed to the handler function in the string <code>error</code>
 * @see Exception.h
 */
void Bootstrap_setAbortHandler(void(*abortHandler)(const char *error, va_list ap));


/**
 * Set the function the library should call for (logging) error messages.
 * If not provided, the library will write error messages to stderr.
 * @param errorHandler The handler function to call when the library
 * emit an error message. The error message is passed to the handler
 * function in the string <code>error</code> with optional variable
 * arguments.
 * @see Exception.h
 */
void Bootstrap_setErrorHandler(void(*errorHandler)(const char *error, va_list ap));


#endif
