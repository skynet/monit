#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>

#include "Bootstrap.h"
#include "Str.h"


/**
 * Str.c unity tests
 */


int main(void) {

        Bootstrap(); // Need to initialize library

        printf("============> Start Str Tests\n\n");

        printf("=> Test1: copy\n");
        {
                char s3[STRLEN];
                printf("\tResult: %s\n", Str_copy(s3, "The abc house", 7));
                assert(Str_isEqual(s3, "The abc"));
                printf("\tTesting for NULL argument\n");
                assert(!Str_copy(NULL, NULL, 7));
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: dup\n");
        {
                char *s4 = Str_dup("abc123");
                printf("\tResult: %s\n", s4);
                assert(Str_isEqual(s4, "abc123"));
                printf("\tTesting for NULL argument\n");
                assert(!Str_dup(NULL));
                FREE(s4);
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: ndup\n");
        {
                char *s5 = Str_ndup("abc123", 3);
                printf("\tResult: %s\n", s5);
                assert(Str_isEqual(s5, "abc"));
                printf("\tTesting for NULL argument\n");
                assert(!Str_ndup(NULL, 3));
                FREE(s5);
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: Str_cat & Str_vcat\n");
        {
                char *s6;
                s6 = Str_cat("%s://%s%s?%s", "https", "foo.bar", 
                                   "/uri", "abc=123");
                printf("\tResult: %s\n", s6);
                assert(Str_isEqual(s6, "https://foo.bar/uri?abc=123"));
                FREE(s6);
                printf("\tTesting for NULL arguments\n");
                s6 = Str_cat(NULL);
                assert(s6==NULL);
                FREE(s6);
        }
        printf("=> Test4: OK\n\n");

        printf("=> Test5: chomp\n");
        {
                char s3[] = "abc\r\n123";
                printf("\tResult: %s\n", Str_chomp(s3));
                assert(Str_isEqual(s3, "abc"));
                printf("\tTesting for NULL argument\n");
                assert(!Str_chomp(NULL));
        }
        printf("=> Test5: OK\n\n");

        printf("=> Test6: trim\n");
        {
                char e[] = "   ";
                char o[] = " a ";
                char s[] = "   abcdef";
                char s4[] = "  \t abc \r\n\t ";
                assert(Str_isEqual(Str_ltrim(s), "abcdef"));
                printf("\tResult: %s\n", Str_trim(s4));
                assert(Str_isEqual(s4, "abc"));
                printf("\tTesting for NULL argument\n");
                assert(!Str_trim(NULL));
                assert(Str_isEqual(Str_ltrim(e), ""));
                memcpy(e, "   ", sizeof("   ") - 1);
                assert(Str_isEqual(Str_rtrim(e), ""));
                memcpy(e, "   ", sizeof("   ") - 1);
                assert(Str_isEqual(Str_trim(e), ""));
                assert(Str_isEqual(Str_ltrim(o), "a "));
                memcpy(o, " a ", sizeof(" a ") - 1);
                assert(Str_isEqual(Str_rtrim(o), " a"));
                memcpy(o, " a ", sizeof(" a ") - 1);
                assert(Str_isEqual(Str_trim(o), "a"));
                assert(Str_isEqual(Str_trim(o), "a"));
        }
        printf("=> Test6: OK\n\n");

        printf("=> Test7: trim quotes\n");
        {
                char s5[] = "\"'abc'\"";
                char s5a[] = "\"'abc";
                char s5b[] = "abc'\"";
                char s5c[] = "'\"";
                char s5d[] = " \t abc def '\"  ";
                printf("\tResult: %s\n", Str_unquote(s5));
                assert(Str_isEqual(s5, "abc"));
                printf("\tResult: %s\n", Str_unquote(s5a));
                assert(Str_isEqual(s5, "abc"));
                printf("\tResult: %s\n", Str_unquote(s5b));
                assert(Str_isEqual(s5, "abc"));
                printf("\tResult: %s\n", Str_unquote(s5b));
                assert(Str_isEqual(s5, "abc"));
                printf("\tTesting for NULL argument\n");
                assert(!Str_unquote(NULL));
                printf("\tTesting for quotes-only argument\n");
                assert(Str_isEqual("", Str_unquote(s5c)));
                printf("\tTesting for quotes and white-space removal\n");
                assert(Str_isEqual("abc def", Str_unquote(s5d)));
        }
        printf("=> Test7: OK\n\n");

        printf("=> Test8: toLowerCase\n");
        {
                char s6[] = "AbC";
                printf("\tResult: %s\n", Str_toLower(s6));
                assert(Str_isEqual(s6, "abc"));
                printf("\tTesting for NULL argument\n");
                assert(!Str_toLower(NULL));
        }
        printf("=> Test8: OK\n\n");

        printf("=> Test9: toUpperCase\n");
        {
                char s7[] = "aBc";
                printf("\tResult: %s\n", Str_toUpper(s7));
                assert(Str_isEqual(s7, "ABC"));
                printf("\tTesting for NULL argument\n");
                assert(!Str_toUpper(NULL));
        }
        printf("=> Test9: OK\n\n");

        printf("=> Test10: parseInt, parseLLong, parseDouble\n");
        {
                char i[STRLEN] = "   -2812 bla";
                char ll[STRLEN] = "  2147483642 blabla";
                char d[STRLEN] = "  2.718281828 this is e";
                char de[STRLEN] = "1.495E+08 kilometer = An Astronomical Unit";
                char ie[STRLEN] = " 9999999999999999999999999999999999999999";
                printf("\tResult:\n");
                printf("\tParsed int = %d\n", Str_parseInt(i));
                assert(Str_parseInt(i)==-2812);
                printf("\tParsed long long = %lld\n", Str_parseLLong(ll));
                assert(Str_parseLLong(ll)==2147483642);
                printf("\tParsed double = %.9f\n", Str_parseDouble(d));
                assert(Str_parseDouble(d)==2.718281828);
                printf("\tParsed double exp = %.3e\n", Str_parseDouble(de));
                assert(Str_parseDouble(de)==1.495e+08);
                TRY
                        Str_parseInt(ie);
                        assert(false);
                CATCH(NumberFormatException)
                        printf("=> Test11: OK\n\n");
                END_TRY;
        }
        printf("=> Test10: OK\n\n");

        printf("=> Test11: replace\n");
        {
                char s9[] = "abccba";
                printf("\tResult: %s\n", Str_replaceChar(s9, 'b', 'X'));
                assert(Str_isEqual(s9, "aXccXa"));
                printf("\tTesting for NULL argument\n");
                assert(!Str_replaceChar(NULL, 'b', 'X'));
        }
        printf("=> Test11: OK\n\n");

        printf("=> Test12: startsWith\n");
        {
                char *a = "mysql://localhost:3306/zild?user=root&password=swordfish";
                printf("\tResult: starts with mysql - %s\n", 
                       Str_startsWith(a, "mysql")?"yes":"no");
                assert(Str_startsWith(a, "mysql"));
                assert(!Str_startsWith(a, "sqlite"));
                assert(Str_startsWith("sqlite", "sqlite"));
                printf("\tTesting for NULL and NUL argument\n");
                assert(!Str_startsWith(a, NULL));
                assert(!Str_startsWith(a, ""));
                assert(!Str_startsWith(NULL, "mysql"));
                assert(!Str_startsWith("", NULL));
                assert(!Str_startsWith(NULL, NULL));
                assert(Str_startsWith("", ""));
                assert(!Str_startsWith("/", "/WEB-INF"));
        }
        printf("=> Test12: OK\n\n");

        printf("=> Test13: endsWith\n");
        {
                char *a = "mysql://localhost:3306";
                printf("\tResult: ends with 3306 - %s\n", Str_endsWith(a, "3306")?"yes":"no");
                assert(Str_endsWith(a, "3306"));
                assert(!Str_endsWith(a, "sqlite"));
                assert(Str_endsWith("sqlite", "sqlite"));
                printf("\tTesting for NULL and NUL argument\n");
                assert(!Str_endsWith(a, NULL));
                assert(Str_endsWith(a, "")); // a ends with 0
                assert(!Str_endsWith(NULL, "mysql"));
                assert(!Str_endsWith("", NULL));
                assert(!Str_endsWith(NULL, NULL));
                assert(Str_endsWith("", ""));
                assert(!Str_endsWith("abc", "defabc"));
        }
        printf("=> Test13: OK\n\n");

        printf("=> Test14: isEqual\n");
        {
                char *a = "mysql://localhost:3306";
                printf("\tResult: is equal - %s\n", Str_isEqual(a, "mysql://localhost:3306")?"yes":"no");
                assert(Str_isEqual("sqlite", "sqlite"));
                printf("\tTesting for NULL and NUL argument\n");
                assert(!Str_isEqual(a, NULL));
                assert(!Str_isEqual(a, ""));
                assert(!Str_isEqual(NULL, "mysql"));
                assert(!Str_isEqual("", NULL));
                assert(!Str_isEqual(NULL, NULL));
                assert(Str_isEqual("", ""));
        }
        printf("=> Test14: OK\n\n");

        printf("=> Test15: trail\n");
        {
                char s[] = "This string will be trailed someplace";
                assert(Str_trunc(NULL, 100) == NULL);
                assert(Str_isEqual(Str_trunc("", 0), ""));
                assert(Str_isEqual(Str_trunc(s, (int)strlen(s)), "This string will be trailed someplace"));
                printf("\tResult: %s\n", Str_trunc(s, 27));
                assert(Str_isEqual(s, "This string will be trailed..."));
                printf("\tResult: %s\n", Str_trunc(s, 0));
                assert(Str_isEqual(s, "..."));
        }
        printf("=> Test15: OK\n\n");

        printf("=> Test16: hash\n");
        {
                char *x = "a";
                char *y = "b";
                char *a = "abc";
                char *b = "bca";
                char *c = "this is a long string";
                char *d = "this is a longer string";
                printf("\tResult: %s -> %d\n", x, Str_hash(x));
                printf("\tResult: %s -> %d\n", y, Str_hash(y));
                assert(Str_hash(x) != Str_hash(y));
                assert(Str_hash(x) == Str_hash(x));
                assert(Str_hash(y) == Str_hash(y));
                printf("\tResult: %s -> %d\n", a, Str_hash(a));
                printf("\tResult: %s -> %d\n", b, Str_hash(b));
                assert(Str_hash(a) != Str_hash(b));
                assert(Str_hash(a) == Str_hash(a));
                assert(Str_hash(b) == Str_hash(b));
                printf("\tResult: %s -> %d\n", c, Str_hash(c));
                printf("\tResult: %s -> %d\n", d, Str_hash(d));
                assert(Str_hash(c) != Str_hash(d));
                assert(Str_hash(c) == Str_hash(c));
                assert(Str_hash(d) == Str_hash(d));
        }
        printf("=> Test16: OK\n\n");

        printf("=> Test17: regular expression match\n");
        {
                char *phone_pattern = "^[-0-9+( )]{7,40}$";
                char *email_pattern = "^[^@ ]+@([-a-zA-Z0-9]+\\.)+[a-zA-Z]{2,}$";
                char *valid_phone1 = "+4797141255";
                char *valid_phone2 = "(47)-97-14-12-55";
                char *invalid_phone1 = "141255";
                char *invalid_phone2 = "(47)971412551234567890123456789012345678901234567890";
                char *invalid_phone3 = "";
                char *invalid_phone4 = "abc123";
                char *valid_email1 = "hauk@TILDESLASH.com";
                char *valid_email2 = "jan-henrik.haukeland@haukeland.co.uk";
                char *invalid_email1 = "hauktildeslash.com";
                char *invalid_email2 = "";
                char *invalid_email3 = "hauk@tildeslashcom";
                char *invalid_email4 = "hauk@æøåtildeslash.com";
                // phone
                printf("\tResult: match(%s, %s)\n", phone_pattern, valid_phone1);
                assert(Str_match(phone_pattern, valid_phone1));
                printf("\tResult: match(%s, %s)\n", phone_pattern, valid_phone2);
                assert(Str_match(phone_pattern, valid_phone2));
                printf("\tResult: match(%s, %s)\n", phone_pattern, invalid_phone1);
                assert(! Str_match(phone_pattern, invalid_phone1));
                printf("\tResult: match(%s, %s)\n", phone_pattern, invalid_phone2);
                assert(! Str_match(phone_pattern, invalid_phone2));
                printf("\tResult: match(%s, %s)\n", phone_pattern, invalid_phone3);
                assert(! Str_match(phone_pattern, invalid_phone3));
                printf("\tResult: match(%s, %s)\n", phone_pattern, invalid_phone4);
                assert(! Str_match(phone_pattern, invalid_phone4));
                // email
                printf("\tResult: match(%s, %s)\n", email_pattern, valid_email1);
                assert(Str_match(email_pattern, valid_email1));
                printf("\tResult: match(%s, %s)\n", email_pattern, valid_email2);
                assert(Str_match(email_pattern, valid_email2));
                printf("\tResult: match(%s, %s)\n", email_pattern, invalid_email1);
                assert(! Str_match(email_pattern, invalid_email1));
                printf("\tResult: match(%s, %s)\n", email_pattern, invalid_email2);
                assert(! Str_match(email_pattern, invalid_email2));
                printf("\tResult: match(%s, %s)\n", email_pattern, invalid_email3);
                assert(! Str_match(email_pattern, invalid_email3));
                printf("\tResult: match(%s, %s)\n", email_pattern, invalid_email4);
                assert(! Str_match(email_pattern, invalid_email4));
        }
        printf("=> Test17: OK\n\n");

        printf("=> Test18: lim\n");
        {
                char *zero = "";
                char *two = "12";
                char *ten = "1234567890";
                assert(! Str_lim(zero, 0));
                assert(!Str_lim(zero, 1));
                assert(Str_lim(two, 0));
                assert(Str_lim(two, 1));
                assert(!Str_lim(two, 2));
                assert(Str_lim(ten, 0));
                assert(Str_lim(ten, 5));
                assert(Str_lim(ten, 9));
                assert(!Str_lim(ten, 10));
                assert(! Str_lim(ten, 100));
        }
        printf("=> Test18: OK\n\n");

        printf("=> Test19: substring\n");
        {
                assert(Str_sub("foo bar baz", "bar"));
                assert(!  Str_sub("foo bar baz", "barx"));
                assert(Str_isEqual(Str_sub("foo bar baz", "baz"), "baz"));
                assert(Str_sub("foo bar baz", "foo bar baz"));
                assert(Str_sub("a", "a"));
                assert(! Str_sub("a", "b"));
                assert(! Str_sub("", ""));
                assert(! Str_sub("foo", ""));
                assert(! Str_sub("abc", "abcdef"));
                assert(! Str_sub("foo", "foo bar"));
                assert(Str_isEqual(Str_sub("foo foo bar", "foo bar"), "foo bar"));
                assert(Str_sub("foo foo bar foo bar baz fuu", "foo bar baz"));
                assert(Str_isEqual(Str_sub("abcd abcc", "abcc"), "abcc"));
        }
        printf("=> Test19: OK\n\n");

        printf("=> Test20: Str_join\n");
        {
                char *p = NULL;
                char dest[10+1] = "xxxxxxxxx";
                char a[] = "abc";
                char *b  = "def";
                char *c  = "xxx123";
                assert(Str_isEqual(Str_join(dest, 10, a, b, "ghi"), "abcdefghi"));
                assert(Str_isEqual(Str_join(dest, 10, p), ""));
                assert(Str_isEqual(Str_join(dest, 10), ""));
                assert(Str_isEqual(Str_join(dest, 10, "012", "3456789", "0123456789"), "0123456789"));
                assert(Str_isEqual(Str_join(dest, 4, "a", "b", "cd", "ghi", "jklmnopq"), "abcd"));
                assert(Str_isEqual(Str_join(dest, 10, a, c + 3), "abc123"));
                Str_join(dest, 0);
                assert(dest[0]==0);
        }
        printf("=> Test20: OK\n\n");

        printf("=> Test21: Str_has\n");
        {
                char *foo = "'bar' (baz)"; 
                assert(Str_has("(')", foo));
                assert(! Str_has(",;", foo));
        }
        printf("=> Test21: OK\n\n");

        printf("=> Test22: Str_curtail\n");
        {
                char s[] = "<text>Hello World</text>"; 
                assert(Str_isByteEqual(Str_curtail(s, "</text>"), "<text>Hello World"));
                assert(Str_isByteEqual(Str_curtail(s, ">"), "<text"));
                assert(Str_isByteEqual(Str_curtail(s, "@"), "<text"));
        }
        printf("=> Test22: OK\n\n");

        printf("=> Test23: Str_bytesToSize\n");
        {
                char str[10];
                Str_bytesToSize(0, str);
                assert(Str_isEqual(str, "0.0 B"));
                Str_bytesToSize(2048, str);
                assert(Str_isEqual(str, "2.0 KB"));
                Str_bytesToSize(2097152, str);
                assert(Str_isEqual(str, "2.0 MB"));
                Str_bytesToSize(2621440, str);
                assert(Str_isEqual(str, "2.5 MB"));
                Str_bytesToSize(9083741824, str);
                assert(Str_isEqual(str, "8.5 GB"));
                Str_bytesToSize(9083741824987653, str);
                assert(Str_isEqual(str, "8.1 PB"));
                Str_bytesToSize(LLONG_MAX, str);
                assert(Str_isEqual(str, "8.0 EB"));
        }
        printf("=> Test23: OK\n\n");


        printf("============> Str Tests: OK\n\n");
        return 0;
}


