#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include "Bootstrap.h"
#include "Str.h"
#include "StringBuffer.h"

/**
 * StringBuffer.c unity tests. 
 */


static void append(StringBuffer_T B, const char *s, ...) {
 	va_list ap;
	va_start(ap, s);
        StringBuffer_vappend(B, s, ap);
	va_end(ap);
}


int main(void) {
        StringBuffer_T sb;

        Bootstrap(); // Need to initialize library

        printf("============> Start StringBuffer Tests\n\n");

        printf("=> Test1: create/destroy\n");
        {
                sb= StringBuffer_new("");
                assert(sb);
                assert(StringBuffer_length(sb)==0);
                StringBuffer_free(&sb);
                assert(sb==NULL);
                sb= StringBuffer_create(1024);
                assert(sb);
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: Append NULL value\n");
        {
                sb= StringBuffer_new("");
                assert(sb);
                StringBuffer_append(sb, NULL);
                assert(StringBuffer_length(sb)==0);
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: Create with string\n");
        {
                sb= StringBuffer_new("abc");
                assert(sb);
                assert(StringBuffer_length(sb)==3);
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: Append string value\n");
        {
                sb= StringBuffer_new("abc");
                assert(sb);
                printf("\tTesting StringBuffer_append:..");
                StringBuffer_append(sb, "def");
                assert(StringBuffer_length(sb)==6);
                printf("ok\n");
                printf("\tTesting StringBuffer_vappend:..");
                append(sb, "%c%s", 'g', "hi");
                assert(StringBuffer_length(sb)==9);
                assert(Str_isEqual(StringBuffer_toString(sb), "abcdefghi"));
                printf("ok\n");
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test4: OK\n\n");

        printf("=> Test5: getCharAt\n");
        {
                sb= StringBuffer_new("abcdefgh");
                assert(sb);
                assert(StringBuffer_charAt(sb, 7)=='h');
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test5: OK\n\n");

        printf("=> Test6: setCharAt\n");
        {
                sb= StringBuffer_new("abcdefgh");
                assert(sb);
                StringBuffer_setCharAt(sb,2,'v');
                assert(StringBuffer_charAt(sb, 2)=='v');
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test6: OK\n\n");

        printf("=> Test7: trim\n");
        {
                sb= StringBuffer_new("\t 'foo bar' \n ");
                assert(Str_isEqual(StringBuffer_toString(StringBuffer_trim(sb)), "'foo bar'"));
                StringBuffer_clear(sb);
                StringBuffer_append(sb, "'foo bar'");
                StringBuffer_trim(sb);
                assert(Str_isEqual(StringBuffer_toString(sb), "'foo bar'"));
                StringBuffer_clear(sb);
                StringBuffer_append(sb, "\t \r \n  ");
                assert(Str_isEqual(StringBuffer_toString(StringBuffer_trim(sb)), ""));
                StringBuffer_free(&sb);
                sb = StringBuffer_create(10);
                StringBuffer_trim(sb);
                assert(StringBuffer_toString(sb)[0] == 0);
                StringBuffer_free(&sb);
        }
        printf("=> Test7: OK\n\n");

        printf("=> Test8: deleteFrom\n");
        {
                sb= StringBuffer_new("abcdefgh");
                assert(sb);
                StringBuffer_delete(sb,3);
                assert(StringBuffer_length(sb)==3);
                assert(StringBuffer_charAt(sb, StringBuffer_length(sb)-1)=='c');
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test8: OK\n\n");

        printf("=> Test9: indexOf and lastIndexOf\n");
        {
                sb= StringBuffer_new("jan-henrik haukeland");
                assert(sb);
                assert(StringBuffer_indexOf(sb, "henrik")==4);
                assert(StringBuffer_indexOf(sb, "an")==1);
                assert(StringBuffer_indexOf(sb, "-")==3);
                assert(StringBuffer_lastIndexOf(sb, "an")==17);
                assert(StringBuffer_indexOf(sb, "")==-1);
                assert(StringBuffer_indexOf(sb, 0)==-1);
                assert(StringBuffer_indexOf(sb, "d")==19);
                assert(StringBuffer_indexOf(sb, "j")==0);
                assert(StringBuffer_lastIndexOf(sb, "d")==19);
                assert(StringBuffer_lastIndexOf(sb, "j")==0);
                assert(StringBuffer_lastIndexOf(sb, "x")==-1);
                assert(StringBuffer_indexOf(sb, "jane")==-1);
                assert(StringBuffer_indexOf(sb, "jan-henrik haukeland")==0);
                assert(StringBuffer_indexOf(sb, "haukeland")==11);
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test9: OK\n\n");

        printf("=> Test10: length and clear\n");
        {
                sb= StringBuffer_new("jan-henrik haukeland");
                assert(sb);
                assert(StringBuffer_length(sb)==20);
                StringBuffer_clear(sb);
                assert(StringBuffer_length(sb)==0);
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test10: OK\n\n");

        printf("=> Test11: out-of-index exception\n");
        {
                sb= StringBuffer_new("abc");
                assert(sb);
                TRY {
                        StringBuffer_charAt(sb, 42);
                        printf("Test 11 failed\n");
                        exit(1); // Should not come here
                } CATCH(AssertException)
                        printf("=> Test11: OK\n\n");
                END_TRY;
                StringBuffer_free(&sb);
        }

        printf("=> Test12: toString value\n");
        {
                sb= StringBuffer_new("abc");
                assert(sb);
                StringBuffer_append(sb, "def");
                assert(Str_isEqual(StringBuffer_toString(sb), "abcdef"));
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test12: OK\n\n");

        printf("=> Test13: internal resize\n");
        {
                int i;
                sb= StringBuffer_new("");
                assert(sb);
                for (i= 0; i<1024; i++)
                        StringBuffer_append(sb, "a");
                assert(StringBuffer_length(sb)==1024);
                assert(StringBuffer_toString(sb)[1023]=='a');
                assert(StringBuffer_toString(sb)[1024]==0);
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test13: OK\n\n");

        printf("=> Test14: substring\n");
        {
                sb= StringBuffer_new("jan-henrik haukeland");
                assert(sb);
                assert(Str_isEqual(StringBuffer_substring(sb, StringBuffer_indexOf(sb, "-")),
                                                 "-henrik haukeland"));
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test14: OK\n\n");

        printf("=> Test15: replace\n");
        {
                printf("\tNothing to replace\n");
                sb= StringBuffer_new("abc?def?");
                assert(sb);
                StringBuffer_replace(sb, "x", "$x");
                assert(Str_isEqual(StringBuffer_toString(sb), "abc?def?"));
                StringBuffer_free(&sb);
                assert(sb==NULL);
                printf("\tReplace and expand\n");
                sb= StringBuffer_new("abc?def?");
                assert(sb);
                StringBuffer_replace(sb, "?", "$x");
                assert(Str_isEqual(StringBuffer_toString(sb), "abc$xdef$x"));
                StringBuffer_free(&sb);
                assert(sb==NULL);
                printf("\tReplace and shrink\n");
                sb= StringBuffer_new("abc$xdef$x");
                assert(sb);
                StringBuffer_replace(sb, "$x", "?");
                assert(Str_isEqual(StringBuffer_toString(sb), "abc?def?"));
                StringBuffer_free(&sb);
                assert(sb==NULL);
                printf("\tReplace with empty string\n");
                sb= StringBuffer_new("abc$xdef$x");
                assert(sb);
                StringBuffer_replace(sb, "$x", "");
                assert(Str_isEqual(StringBuffer_toString(sb), "abcdef"));
                StringBuffer_free(&sb);
                assert(sb==NULL);
                printf("\tReplace with same length\n");
                sb= StringBuffer_new("foo bar baz foo bar baz");
                assert(sb);
                StringBuffer_replace(sb, "baz", "bar");
                assert(Str_isEqual(StringBuffer_toString(sb), "foo bar bar foo bar bar"));
                StringBuffer_free(&sb);
                assert(sb==NULL);
                printf("\tRemove words and test traceback\n");
                sb= StringBuffer_new("foo bar baz foo foo bar baz");
                assert(sb);
                StringBuffer_replace(sb, "baz", "bar");
                assert(Str_isEqual(StringBuffer_toString(sb), "foo bar bar foo foo bar bar"));
                StringBuffer_replace(sb, "foo bar ", "");
                assert(Str_isEqual(StringBuffer_toString(sb), "bar foo bar"));
                StringBuffer_free(&sb);
                assert(sb==NULL);
                printf("\tReplace all elements\n");
                sb= StringBuffer_new("aaaaaaaaaaaaaaaaaaaaaaaa");
                assert(sb);
                StringBuffer_replace(sb, "a", "b");
                assert(Str_isEqual(StringBuffer_toString(sb), "bbbbbbbbbbbbbbbbbbbbbbbb"));
                StringBuffer_free(&sb);
                assert(sb==NULL);
                printf("\tReplace and expand with resize of StringBuffer\n");
                sb= StringBuffer_new("insert into(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) values (1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,01,2,3);");
                assert(sb);
                StringBuffer_replace(sb, "?", "$x");
                assert(Str_isEqual(StringBuffer_toString(sb), "insert into($x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x, $x) values (1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,01,2,3);"));
                StringBuffer_free(&sb);
                assert(sb==NULL);
        }
        printf("=> Test15: OK\n\n");

        printf("============> StringBuffer Tests: OK\n\n");

        return 0;
}
