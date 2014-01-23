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

#include "system/System.h"
#include "Thread.h"


/**
 * Implementation of the Thread.h interface
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ----------------------------------------------------------- Definitions */


static pthread_attr_t myDetachStateAttribute;
static pthread_once_t once_control = PTHREAD_ONCE_INIT;


/* --------------------------------------------------------------- Private */


/* Setup common thread attribute */
static void init_once(void) { 
        int status = pthread_attr_init(&myDetachStateAttribute);
        if (status != 0)
                THROW(AssertException, "pthread_attr_init -- %s", System_getError(status));
        status = pthread_attr_setdetachstate(&myDetachStateAttribute, PTHREAD_CREATE_DETACHED);
        if (status != 0) {
                pthread_attr_destroy(&myDetachStateAttribute);
                THROW(AssertException, "pthread_attr_setdetachstate -- %s", System_getError(status));
        }
}


/* ----------------------------------------------------- Protected Methods */


/* Called from Bootstrap() */
void Thread_init(void) { pthread_once(&once_control, init_once); }


/* Called at program termination for cleanup */
void Thread_fini(void) { pthread_attr_destroy(&myDetachStateAttribute); }


/* ---------------------------------------------------------------- Public */


void Thread_createDetached(Thread_T *thread, void *(*threadFunc)(void *threadArgs), void *threadArgs) {
        assert(thread);
        assert(threadFunc);
        int status = pthread_create(thread, &myDetachStateAttribute, threadFunc, threadArgs);
        if (status != 0)
                THROW(AssertException, "pthread_create -- %s", System_getError(status));
}


