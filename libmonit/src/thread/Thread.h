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


#ifndef THREAD_INCLUDED
#define THREAD_INCLUDED
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>
#include "system/System.h"


/**
 * General purpose <b>Thread</b> abstractions. This interface  defines object
 * types and methods for handling threads, synchronization and semaphores. 
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/** @cond hidden */
#define wrapper(F) do { \
        int status= (F); if (! (status == 0 || status==ETIMEDOUT)) \
        THROW(AssertException, "%s -- %s", #F, System_getError(status)); \
} while (0)
/** @endcond */
/** @name Abstract Data Types */
//@{
/**
 * Thread object type
 * @hideinitializer
 */
#define Thread_T pthread_t
/**
 * Semaphore object type
 * @hideinitializer
 */
#define Sem_T   pthread_cond_t			  
/**
 * Mutex object type
 * @hideinitializer
 */
#define Mutex_T pthread_mutex_t
/**
 * Read/Write Lock object type
 * @hideinitializer
 */
#define Lock_T pthread_rwlock_t
/**
 * Thread Data object type
 * @hideinitializer
 */
#define ThreadData_T pthread_key_t
//@}
/** @name Thread methods */
//@{
/**
 * Create a new thread
 * @param thread The thread to create
 * @param threadFunc The thread routine to execute
 * @param threadArgs Arguments to <code>threadFunc</code>
 * @exception AssertException If thread creation failed
 * @hideinitializer
 */
#define Thread_create(thread, threadFunc, threadArgs) \
        wrapper(pthread_create(&thread, NULL, threadFunc, (void*)threadArgs))
/**
 * Returns the thread ID of the calling thread
 * @return The id of the calling thread
 * @hideinitializer
 */
#define Thread_self() pthread_self()
/**
 * Detach a thread
 * @param thread The thread to detach
 * @exception AssertException If detaching the thread failed
 * @hideinitializer
 */
#define Thread_detach(thread) wrapper(pthread_detach(thread))
/**
 * Cancel execution of a thread
 * @param thread The thread to cancel
 * @exception AssertException If thread cancelation failed
 * @hideinitializer
 */
#define Thread_cancel(thread) wrapper(pthread_cancel(thread))
/**
 * Wait for thread termination
 * @param thread The thread to wait for
 * @exception AssertException If thread join failed
 * @hideinitializer
 */
#define Thread_join(thread) wrapper(pthread_join(thread, NULL))
//@}
/** @name Semaphore methods */
//@{
/**
 * Initialize a new semaphore
 * @param sem The semaphore to initialize
 * @exception AssertException If initialization failed
 * @hideinitializer
 */
#define Sem_init(sem) wrapper(pthread_cond_init(&sem, NULL))
/**
 * Wait on a semaphore
 * @param sem The semaphore to wait on
 * @param mutex A mutex to unlock on wait
 * @exception AssertException If wait failed
 * @hideinitializer
 */
#define Sem_wait(sem, mutex) wrapper(pthread_cond_wait(&sem, &(mutex)))
/**
 * Unblock a thread waiting for a semaphore
 * @param sem The semaphore to signal
 * @exception AssertException If signal failed
 * @hideinitializer
 */
#define Sem_signal(sem) wrapper(pthread_cond_signal(&sem))
/**
 * Unblock all threads waiting for a semaphore
 * @param sem The semaphore to broadcast
 * @exception AssertException If broadcast failed
 * @hideinitializer
 */
#define Sem_broadcast(sem) wrapper(pthread_cond_broadcast(&sem))
/**
 * Destroy a semaphore
 * @param sem The semaphore to destroy
 * @exception AssertException If destroy failed
 * @hideinitializer
 */
#define Sem_destroy(sem) wrapper(pthread_cond_destroy(&sem))
/**
 * Wait on a semaphore for a specific amount of time. During the wait
 * the mutex is unlocked and reacquired afterwards
 * @param sem The semaphore to wait on
 * @param mutex A mutex to unlock on wait
 * @param time time to wait
 * @exception AssertException If the timed wait failed
 * @hideinitializer
 */
#define Sem_timeWait(sem, mutex, time) \
        wrapper(pthread_cond_timedwait(&sem, &(mutex), &time))
//@}
/** @name Mutex methods */
//@{
/**
 * Initialize a new mutex
 * @param mutex The mutex to initialize
 * @exception AssertException If initialization failed
 * @hideinitializer
 */
#define Mutex_init(mutex) wrapper(pthread_mutex_init(&(mutex), NULL))
/**
 * Destroy a the given mutex
 * @param mutex The mutex to destroy
 * @exception AssertException If destroy failed
 * @hideinitializer
 */
#define Mutex_destroy(mutex) wrapper(pthread_mutex_destroy(&(mutex)))
/**
 * Locks a mutex
 * @param mutex The mutex to lock
 * @exception AssertException If mutex lock failed
 * @hideinitializer
 */
#define Mutex_lock(mutex) wrapper(pthread_mutex_lock(&(mutex)))
/**
 * Unlocks a mutex
 * @param mutex The mutex to unlock
 * @exception AssertException If mutex unlock failed
 * @hideinitializer
 */
#define Mutex_unlock(mutex) wrapper(pthread_mutex_unlock(&(mutex)))
/**
 * Defines a block of code to execute after the given mutex is locked
 * @param mutex The mutex to lock
 * @hideinitializer
 */
#define LOCK(mutex) do { Mutex_T *_yymutex= &(mutex); assert(pthread_mutex_lock(_yymutex)==0);
/**
 * Ends a LOCK block
 * @hideinitializer
 */
#define END_LOCK assert(pthread_mutex_unlock(_yymutex)==0); } while (0)
//@}
/** @name Read/Write Lock methods */
//@{
/**
 * Initialize a new read/write lock
 * @param lock The lock to initialize
 * @exception AssertException If initialization failed
 * @hideinitializer
 */
#define Lock_init(lock) wrapper(pthread_rwlock_init(&(lock), NULL))
/**
 * Destroy a read/write lock
 * @param lock The lock to destroy
 * @exception AssertException If destroy failed
 * @hideinitializer
 */
#define Lock_destroy(lock) wrapper(pthread_rwlock_destroy(&(lock)))
/**
 * Acquire a read/write lock for reading
 * @param lock A read/write lock
 * @exception AssertException If failed
 * @hideinitializer
 */
#define Lock_read(lock) wrapper(pthread_rwlock_rdlock(&(lock)))
/**
 * Acquire a read/write lock for writing
 * @param lock A read/write lock
 * @exception AssertException If failed
 * @hideinitializer
 */
#define Lock_write(lock) wrapper(pthread_rwlock_wrlock(&(lock)))
/**
 * Release a read/write lock
 * @param lock A read/write lock
 * @exception AssertException If failed
 * @hideinitializer
 */
#define Lock_unlock(lock) wrapper(pthread_rwlock_unlock(&(lock)))
/**
 * Defines a block of code to execute after the given read locked is acquired
 * @param lock The read lock
 * @hideinitializer
 */
#define RLOCK(lock) do { Lock_T *_yyrlock= &(lock); assert(pthread_rwlock_rdlock(_yyrlock)==0);
/**
 * Ends a RLOCK block
 * @hideinitializer
 */
#define END_RLOCK assert(pthread_rwlock_unlock(_yyrlock)==0); } while (0)
/**
 * Defines a block of code to execute after the given write locked is acquired
 * @param lock The write lock
 * @hideinitializer
 */
#define WLOCK(lock) do { Lock_T *_yywlock= &(lock); assert(pthread_rwlock_wrlock(_yywlock)==0);
/**
 * Ends a RLOCK block
 * @hideinitializer
 */
#define END_WLOCK assert(pthread_rwlock_unlock(_yywlock)==0); } while (0)
//@}
/** @name Thread data methods */
//@{
/**
 * Creates a thread-specific data key. 
 * @param key The ThreadData_T key to create
 * @exception AssertException If thread data creation failed
 * @hideinitializer
 */
#define ThreadData_create(key) wrapper(pthread_key_create(&(key), NULL))
/**
 * Sets a thread-specific data value. The key is of type ThreadData_T
 * @param key The ThreadData_T key to set a new value for
 * @param value The value for key
 * @exception AssertException If setting thread data failed
 * @hideinitializer
 */
#define ThreadData_set(key, value) wrapper(pthread_setspecific((key), (value)))
/**
 * Gets a thread-specific data value
 * @param key The ThreadData_T key
 * @return value of key or NULL of no value was set for the key
 * @hideinitializer
 */
#define ThreadData_get(key) pthread_getspecific((key))
//@}


/* ----------------------------------------------------------------- Methods */


//<< Start filter-out

/**
 * Initialize Threads. This method should be called at program startup
 */
void Thread_init(void);


/**
 * Shutdown and cleanup threads. This method should be called at program termination
 */
void Thread_fini(void);


//>> End filter-out


/**
 * Create a new thread in a detached state
 * @param thread The thread to create
 * @param threadFunc The thread routine to execute
 * @param threadArgs Arguments to <code>threadFunc</code>
 * @exception AssertException If thread creation failed
 */
void Thread_createDetached(Thread_T *thread, void *(*threadFunc)(void *threadArgs), void *threadArgs);

#endif
