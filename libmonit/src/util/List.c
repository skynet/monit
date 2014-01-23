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

#include <stdio.h>
#include <strings.h>
#include <stdarg.h>

#include "Str.h"
#include "List.h"


/**
 * Implementation of the List interface. A freelist is used to retain
 * deleted nodes for reuse.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ----------------------------------------------------------- Definitions */


#define T List_T


/* --------------------------------------------------------------- Private */


static inline list_t new_node(T L, void *e, list_t next) {
        list_t p;
        if (L->freelist) {
                p = L->freelist;
                L->freelist = p->next;
        } else
                p = ALLOC(sizeof *(p));
        p->e = e;
        p->next = next;
        return p;
}


/* ---------------------------------------------------------------- Public */


T List_new(void) {
 	T L;
        NEW(L);
	return L;
}


void List_free(T *L) {
        list_t p, q;
        assert(L && *L);
        for (p = (*L)->head; p; p = q) {
                q = p->next;
                FREE(p);
        }
        for (p = (*L)->freelist; p; p = q) {
                q = p->next;
                FREE(p);
        }
        FREE(*L);
}


void List_push(T L, void *e) {
        assert(L);
        list_t p = new_node(L, e, L->head);
        if (L->head == NULL)
                L->tail = p;
        L->head = p;
        L->length++;
        L->timestamp++;
}


void *List_pop(T L) {
        assert(L);
        if (L->head) {
                list_t p = L->head;
                L->head = L->head->next;
                L->length--;
                L->timestamp++;
                p->next = L->freelist;
                L->freelist = p;
                return p->e;
        } 
        return NULL;
}


void List_append(T L, void *e) {
        list_t p;
        assert(L);
        p = new_node(L, e, NULL);
        if (L->head == NULL)
                L->head = p;
        else
                L->tail->next = p;
        L->tail = p;
        L->length++;
        L->timestamp++;
}


void *List_remove(T L, void *e) {
        assert(L);
        if (e && L->head) {
                list_t p, q;
                if (L->head->e == e)
                        return List_pop(L);
                for (p = L->head; p; p = q) {
                        q = p->next;
                        if (q && (q->e == e)) {
                                p->next = q->next;
                                if (q == L->tail)
                                        L->tail = p;
                                p = q;
                                L->length--;
                                L->timestamp++;
                                p->next = L->freelist;
                                L->freelist = p;
                                return p->e;
                        }
                }
        }
        return NULL;
}


void List_cat(T L, T list) {
        assert(L);
        assert(list);
        if (L != list)
                for (list_t p = list->head; p; p = p->next)
                        List_append(L, p->e);
}


void List_reverse(T L) {
        list_t head, next, list;
        assert(L);
        head = NULL;
        list = L->head;
        L->tail = L->head;
	for (; list; list = next) {
                next = list->next;
                list->next = head;
                head = list;
	}
        L->head = head;
}


int List_length(T L) {
        assert(L);
        return L->length;
}


void List_clear(T L) {
        assert(L);
        if (L->tail) {
                L->tail->next = L->freelist;
                L->freelist = L->head;
        }
        L->tail = L->head = NULL;
        L->length = 0;
}


void List_map(T L, void (*apply)(void *e, void *ap), void *ap) {
        int stamp;
        list_t p;
        assert(L);
        stamp = L->timestamp;
        assert(apply);
        for (p = L->head; p; p = p->next) {
                apply(p->e, ap);
                assert(L->timestamp == stamp);
        }
}


void **List_toArray(T L) {
        assert(L);
        int i = 0;
        void **array = ALLOC((L->length + 1) * sizeof *(array)); 
        for (list_t p = L->head; p; p = p->next, i++)
                array[i] = p->e;
        array[i] = NULL;
        return array;
}


