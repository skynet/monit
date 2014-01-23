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

#include <stdarg.h>

#include "Thread.h"
#include "Exception.h"
#include "Bootstrap.h"


/**
 * Implementation of the Bootstrap interface
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ----------------------------------------------------------- Definitions */


void(*_AbortHandler)(const char *error, va_list ap) = NULL;
void(*_ErrorHandler)(const char *error, va_list ap) = NULL;


/* ---------------------------------------------------------------- Public */


void Bootstrap(void) {
        Exception_init();
        Thread_init();
}


void Bootstrap_setAbortHandler(void(*abortHandler)(const char *error, va_list a)) {
        _AbortHandler = abortHandler;
}


void Bootstrap_setErrorHandler(void(*errorHandler)(const char *error, va_list ap)) {
        _ErrorHandler = errorHandler;
}
