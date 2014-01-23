#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>

#include "Bootstrap.h"
#include "Str.h"
#include "List.h"

/**
 * List.c unity tests.
 */


static void apply(void *value, void *ap) {
        *(int *)ap += 1;
}



int main(void) {
        List_T L = NULL;

        Bootstrap(); // Need to initialize library

        printf("============> Start List Tests\n\n");

        printf("=> Test0: create\n");
        {
                L = List_new();
                assert(L);
                List_free(&L);
        }
        printf("=> Test0: OK\n\n");

        printf("=> Test1: List_push() & List_length()\n");
        {
                L = List_new();
                List_push(L, "1");
                List_push(L, "2");
                List_push(L, "3");
                List_push(L, "4");
                List_push(L, "5");
                List_push(L, "6");
                List_push(L, "7");
                List_push(L, "8");
                List_push(L, "9");
                List_push(L, "10");
                List_push(L, "11");
                List_push(L, "12");
                List_push(L, "13");
                List_push(L, "14");
                List_push(L, "15");
                assert(Str_isEqual(L->tail->e, "1"));
                assert(Str_isEqual(L->head->e, "15"));
                assert(List_length(L) == 15);
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: List_pop()\n");
        {
                int i= 0;
                list_t p;
                while (List_pop(L)) ;
                assert(List_length(L) == 0);
                // Ensure that nodes are retained in the freelist
                for (p= L->freelist; p; p= p->next) i++;
                assert(i == 15);
                List_free(&L);
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: List_append()\n");
        {
                L = List_new();
                List_append(L, "1");
                List_append(L, "2");
                List_append(L, "3");
                List_append(L, "4");
                List_append(L, "5");
                List_append(L, "6");
                List_append(L, "7");
                List_append(L, "8");
                List_append(L, "9");
                List_append(L, "10");
                List_append(L, "11");
                List_append(L, "12");
                List_append(L, "13");
                List_append(L, "14");
                List_append(L, "15");
                assert(Str_isEqual(L->tail->e, "15"));
                assert(Str_isEqual(L->head->e, "1"));
                assert(List_length(L) == 15);
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: List_cat()\n");
        {
                List_T t= List_new();
                List_append(t, "a");
                List_append(t, "b");
                List_append(t, "c");
                List_append(t, "d");
                List_cat(L, t);
                assert(Str_isEqual(L->tail->e, "d"));
                assert(Str_isEqual(L->head->e, "1"));
                assert(List_length(L) == 19);
        }
        printf("=> Test4: OK\n\n");

        printf("=> Test5: List_reverse()\n");
        {
                list_t p;
                List_T l= List_new();
                List_append(l, "a");
                List_append(l, "b");
                List_append(l, "c");
                List_append(l, "d");
                printf("\tList before reverse: ");
                for (p= l->head; p; p= p->next)
                        printf("%s%s", (char*)p->e, p->next?"->":"\n");
                assert(Str_isEqual(l->head->e, "a"));
                assert(Str_isEqual(l->tail->e, "d"));
                List_reverse(l);
                printf("\tList after reverse: ");
                for (p= l->head; p; p= p->next)
                        printf("%s%s", (char*)p->e, p->next?"->":"\n");
                assert(Str_isEqual(l->head->e, "d"));
                assert(Str_isEqual(l->tail->e, "a"));
                List_free(&l);
        }
        printf("=> Test5: OK\n\n");

        printf("=> Test6: List_map()\n");
        {
                int i = 0;
                List_map(L, apply, &i);
                assert(i == 19);
        }
        printf("=> Test6: OK\n\n");

        printf("=> Test7: List_clear()\n");
        {
                List_clear(L);
                assert(List_length(L) == 0);
                assert(L->freelist);
        }
        printf("=> Test7: OK\n\n");

        List_free(&L);

        printf("=> Test8: List malloc\n");
        {
                L = List_new();
                List_push(L, "1");
                List_push(L, "2");
                List_push(L, "3");
                List_push(L, "4");
                List_push(L, "5");
                List_push(L, "6");
                List_push(L, "7");
                List_push(L, "8");
                List_push(L, "9");
                List_push(L, "10");
                List_push(L, "11");
                List_push(L, "12");
                List_push(L, "13");
                List_push(L, "14");
                List_push(L, "15");
                assert(Str_isEqual(L->tail->e, "1"));
                assert(Str_isEqual(L->head->e, "15"));
                assert(List_length(L) == 15);
                List_clear(L);
                List_append(L, "1");
                List_append(L, "2");
                List_append(L, "3");
                List_append(L, "4");
                List_append(L, "5");
                List_append(L, "6");
                List_append(L, "7");
                List_append(L, "8");
                List_append(L, "9");
                List_append(L, "10");
                List_append(L, "11");
                List_append(L, "12");
                List_append(L, "13");
                List_append(L, "14");
                List_append(L, "15");
                assert(Str_isEqual(L->tail->e, "15"));
                assert(Str_isEqual(L->head->e, "1"));
                assert(List_length(L) == 15);
                List_free(&L);
        }
        printf("=> Test8: OK\n\n");

        printf("=> Test9: List remove\n");
        {
                char *one = "1";
                char *two = "2";
                L = List_new();
                printf("\tRemove from empty list.. ");
                assert(List_remove(L, "1") == NULL);
                printf("OK\n");
                List_push(L, one);
                printf("\tRemove from 1 element list.. ");
                assert(List_remove(L, one) == one);
                assert(List_length(L) == 0);
                printf("OK\n");
                List_push(L, one);
                List_push(L, two);
                printf("\tRemove last from list.. ");
                assert(List_remove(L, two) == two);
                assert(List_length(L) == 1);
                printf("OK\n");
                List_append(L, two);
                List_append(L, two);
                List_append(L, two);
                List_append(L, "5");
                printf("\tRemove first occurrence.. ");
                assert(List_remove(L, two) == two);
                assert(List_length(L) == 4);
                printf("OK\n");
                List_free(&L);
        }
        printf("=> Test9: OK\n\n");

        printf("=> Test10: check pointers\n");
        {
                L = List_new();
                printf("\tCheck pop.. ");
                List_push(L, "1");
                List_push(L, "2");
                List_pop(L);
                List_pop(L);
                List_push(L, "1");
                assert(L->head == L->tail);
                List_pop(L);
                List_append(L, "1");
                assert(L->head == L->tail);
                printf("OK\n");
                printf("\tCheck remove.. ");
                List_push(L, "1");
                List_append(L, "2");
                List_remove(L, "2");
                List_remove(L, "1");
                assert(L->head == L->tail);
                printf("OK\n");
                List_free(&L);
        }
        printf("=> Test10: OK\n\n");

        printf("=> Test11: List_toArray()\n");
        {
                List_T l = List_new();
                List_append(l, "a");
                List_append(l, "b");
                List_append(l, "c");
                List_append(l, "d");
                char **array = (char**)List_toArray(l);
                assert(Str_isEqual(array[0], "a"));
                assert(Str_isEqual(array[1], "b"));
                assert(Str_isEqual(array[2], "c"));
                assert(Str_isEqual(array[3], "d"));
                assert(array[4] == NULL);
                FREE(array);
                List_free(&l);
        }
        printf("=> Test11: OK\n\n");

        printf("============> List Tests: OK\n\n");

        return 0;
}


