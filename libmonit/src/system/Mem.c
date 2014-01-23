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

#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#include "assert.h"
#include "System.h"
#include "MemoryException.h"


/**
 * Implementation of the Mem interface
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ---------------------------------------------------------------- Public */


void *Mem_alloc(long nbytes, const char *func, const char *file, int line){
	void *ptr;
	assert(nbytes > 0);
	ptr = malloc(nbytes);
	if (ptr == NULL)
                Exception_throw(&(MemoryException), func, file, line, System_getLastError());
	return ptr;
}


void *Mem_calloc(long count, long nbytes, const char *func, const char *file, int line) {
	void *ptr;
	assert(count > 0);
	assert(nbytes > 0);
	ptr = calloc(count, nbytes);
	if (ptr == NULL)
                Exception_throw(&(MemoryException), func, file, line, System_getLastError());
	return ptr;
}


void Mem_free(void *ptr, const char *func, const char *file, int line) {
	if (ptr)
		free(ptr);
}


void *Mem_resize(void *ptr, long nbytes, const char *func, const char *file, int line) {
	assert(nbytes > 0);
        if (! ptr)
                return Mem_alloc(nbytes, func, file, line); 
	ptr = realloc(ptr, nbytes);
	if (ptr == NULL)
                Exception_throw(&(MemoryException), func, file, line, System_getLastError());
	return ptr;
}
