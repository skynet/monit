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


#ifndef CONFIG_INCLUDED
#define CONFIG_INCLUDED


/**
 * Global defines, macros and types
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


#include <errno.h>
#include <limits.h>
#include <string.h>

#include "xconfig.h"
#include "assert.h"
#include "system/Mem.h"


/* ----------------------------------- Error, Exceptions and report macros */


/**
 * The standard abort routine
 */
#define ABORT	System_abort


/**
 * The standard error routine
 */
#define ERROR	System_error


/* ------------------------------------------------------------ Exceptions */


#include "AssertException.h"
#include "IOException.h"
#include "NumberFormatException.h"


/* ------------------------------------------ General Purpose value macros */


/**
 * Standard String length
 */
#define STRLEN 256


/* ---------------------------------------------------------- Build macros */


/* Mask out GCC __attribute__ extension for non-gcc compilers. */
#ifndef __GNUC__
#define __attribute__(x)
#endif


/* ------------------------------------------------------ Type definitions */


#if !defined(SOLARIS) && !defined(AIX)
/**
 * The internal 8-bit char type
 */
typedef unsigned char uchar_t;


/**
 * The internal 32 bits integer type
 */
typedef  unsigned int uint32_t;


/**
 * The internal boolean integer type
 */
typedef enum {false=0, true} boolean_t;
#else
#define false 0
#define true  1
#endif


#endif


