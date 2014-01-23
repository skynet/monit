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


#ifndef LIST_INCLUDED
#define LIST_INCLUDED


/**
 * A <b>List</b> is a sequence of zero or more elements. A List can be used
 * as a LIFO (last in, first out) stack by using List_push() and List_pop()
 * or as a FIFO (first in, first out) queue by using List_append() and 
 * List_pop(). These operations takes constant time.
 *
 * The List ADT representation is revealed in this interface for easy access
 * by clients. The representation is trivial; a structure with two fields. 
 * The first field, <code>e</code>, is a pointer to an element added to the
 * list and <code>next</code> points to the next node in the List or to NULL
 * if there are no more nodes. In addition, the two variables <code>head</code>
 * and <code>tail</code> are pointers to respectively the first and last node
 * in the List. The variable <code>freelist</code> is used to retain popped
 * list_t nodes for reuse. 
 *
 * This class is reentrant but not thread-safe
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


#define T List_T
typedef struct T *T;
/** @cond hide */
typedef struct list_t {void *e; struct list_t *next;} *list_t;
struct T {
        int length;
        int timestamp;
        list_t  head, tail, freelist;
};
/** @endcond */


/**
 * Create a new List object.
 * @return A List object
 * @exception MemoryException if allocation failed
 */
T List_new(void);


/**
 * Destroy a List object and release allocated resources. Call this
 * method to release a List object allocated with List_new()
 * @param L A List object reference
*/
void List_free(T *L);


/**
 * Add <code>e</code> to the beginning of the List
 * @param L A List object
 * @param e An element to add to the beginning of the List
 * @exception MemoryException if allocation failed
 */
void List_push(T L, void *e);


/**
 * Remove the first element from the List
 * @param L A List object
 * @return The element removed from the beginning of the List
 */
void *List_pop(T L);


/**
 * Append <code>e</code> to the end of the List
 * @param L A List object
 * @param e An element to append to the end of the List
 */
void List_append(T L, void *e);


/**
 * Remove the first occurrence of the element <code>e</code> from the List
 * @param L A List object
 * @param e The element to remove from the list
 * @return The element removed from the List or NULL if <code>e</code> 
 * was not found in the List
 */
void *List_remove(T L, void *e);


/**
 * Concatenate <code>list</code> with this List. All nodes in 
 * <code>list</code> are appended to L. <code>list</code> 
 * is not changed
 * @param L A List object
 * @param list A List to append to the end of this List
 */
void List_cat(T L, T list);


/**
 * Reverse the order of the elements in the List
 * @param L A List object
 */
void List_reverse(T L);


/**
 * Returns the number of elements in the List.
 * @param L A List object
 * @return Number of elements in the List
 */
int List_length(T L);


/**
 * Clear this List so it contains no elements. The List will be empty after
 * this call. 
 * @param L A List object
 */
void List_clear(T L);


/**
 * Apply the visitor function, <code>apply</code> for each element in 
 * the List. Clients can pass an application specific pointer, 
 * <code>ap</code>, to List_map() and this pointer is passed along to the
 * <code>apply</code> function at each call. It is a checked runtime error
 * for <code>apply</code> to change the List. 
 * @param L A List object
 * @param apply The function to apply
 * @param ap An application-specific pointer. If such a pointer is 
 * not needed, just use NULL
 * @exception AssertException if <code>apply</code> change the List
 */
void List_map(T L, void (*apply)(void *e, void *ap), void *ap);


/**
 * Creates a N + 1 length array containing all the elements 
 * in this List. The last element in the array is NULL. The
 * caller is responsible for deallocating the array.
 * @param L A List object
 * @return A pointer to the first element in the array
 * @exception MemoryException if allocation failed
 */
void **List_toArray(T L);

#undef T
#endif
