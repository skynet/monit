/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 * Copyright (C) 1994,1995,1996,1997 by David R. Hanson.
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


#ifndef ASSERTION_INCLUDED
#define ASSERTION_INCLUDED
#include <exceptions/AssertException.h>


/**
 * The assert() macro tests the given expression and if it is false, raise
 * an AssertException. Unless a previous installed exception handler catch
 * the exception, it will cause the application to abort. If expression is 
 * true, the assert() macro does nothing. <small>The assert() macro is 
 * required and may <b>not</b> be removed at compile time.</small>
 * @see AssertException.h 
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */

#undef assert
/** @cond hide */
extern void assert(int e);
/** @endcond */


/**
 * Evaluate the given expression <code>e</code> and if false raise
 * an AssertException
 * @param e The expression to evaluate
 * @exception AssertException if <code>e</code> is false
 * @hideinitializer
 */
#define assert(e) ((void)((e)||(Exception_throw(&(AssertException), __func__, __FILE__, __LINE__, #e),0)))


#endif
