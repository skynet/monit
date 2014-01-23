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


#ifndef SYSTEM_INCLUDED
#define SYSTEM_INCLUDED


/**
 * System routines
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/**
 * Returns a String describing the last system error
 * @return The last error message
 */
const char *System_getLastError(void);


/**
 * Returns a String describing the error code
 * @param error error code to lookup
 * @return The error string for the given code
 */
const char *System_getError(int error);


/**
 * Prints the given error message to <code>stderr</code> and 
 * <code>abort(3)</code> the application. If an AbortHandler callback 
 * function is defined for the library, this function is called instead.
 * @param e A formated (printf-style) message string
 */
void System_abort(const char *e, ...) __attribute__((format (printf, 1, 2)));


/**
 * Prints the given error message to <code>stderr</code>. If an ErrorHandler
 * callback function is defined for the library, this function is called instead.
 * @param e A formated (printf-style) message string
 */
void System_error(const char *e, ...) __attribute__((format (printf, 1, 2)));


#endif
