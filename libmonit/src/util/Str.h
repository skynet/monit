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


#ifndef STR_INCLUDED
#define STR_INCLUDED
#include <stdarg.h>


/**
 * General purpose <b>String</b> utility <b>class methods</b>.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/**
 * Test if the given string is defined. That is; not NULL nor the 
 * empty ("") string
 * @param s The string to test
 * @return true if s is defined, otherwise false
 * @hideinitializer
 */
#define STR_DEF(s) ((s) && *(s))


/**
 * Test if the given string is NULL or the empty ("") string
 * @param s The string to test
 * @return true if s is NULL or the empty string, otherwise false
 * @hideinitializer
 */
#define STR_UNDEF(s) (! STR_DEF(s))


/**
 * Removes everything from the first newline (CR|LF)
 * @param s A string to be chomped
 * @return The chomped string
 */
char *Str_chomp(char *s);


/**
 * Remove leading and trailing white space [ \\t\\r\\n]
 * from the string.
 * @param s A string
 * @return s with leading and trailing spaces removed
 */
char *Str_trim(char *s);


/**
 * Remove leading white space [ \\t\\r\\n] from the string. 
 * @param s A string
 * @return s with leading spaces removed
 */
char *Str_ltrim(char *s);


/**
 * Remove trailing white space [ \\t\\r\\n] from the string
 * @param s A string
 * @return s with trailing spaces removed
 */
char *Str_rtrim(char *s);


/**
 * Remove any enclosing quotes ["'] and white-space from the string
 * @param s A string
 * @return s with any enclosed quotes and white-space removed
 */
char *Str_unquote(char *s);


/**
 * Converts the given string to lower case
 * @param s A string
 * @return s converted to lower case letters
 */
char *Str_toLower(char *s);


/**
 * Converts the given string to upper case
 * @param s A string
 * @return s converted to upper case letters
 */
char *Str_toUpper(char *s);


/**
 * Parses the string argument as a signed decimal integer.
 * @param s A string
 * @return The integer represented by the string argument
 * @exception NumberFormatException If the String does not contain a
 * parsable int
 */
int Str_parseInt(const char *s);


/**
 * Parses the string argument as a signed long long in base 10. 
 * @param s A string
 * @return The long long represented by the string argument.
 * @exception NumberFormatException If the String does not contain a
 * parsable long long
 */
long long int Str_parseLLong(const char *s);


/**
 * Parses the string argument as a double. 
 * @param s A string
 * @return The double represented by the string argument.
 * @exception NumberFormatException If the String does not contain a
 * parsable double
 */
double Str_parseDouble(const char *s);


/**
 * Replace all occurrences of the <code>old</code> char in
 * <code>s</code> with the <code>new</code> char.
 * @param s A string
 * @param o The old char
 * @param n The new char
 * @return s where all occurrence of old are replaced with new
 */
char *Str_replaceChar(char *s, char o, char n);


/**
 * Returns true if <i>a</i> starts with <i>b</i>. The test is 
 * <i>case-insensitive</i> but depends on that all characters
 * in the two strings can be translated in the current locale. 
 * <code>b</code> is assumed to be the substring of <code>a</code>.
 * This means that if <code>a</code> is shorter than <code>b</code>, 
 * this method returns false
 * @param a The string to search for b in
 * @param b The sub-string to test a against
 * @return true if a starts with b, otherwise false
 */
int Str_startsWith(const char *a, const char *b);


/**
 * Returns true if <i>a</i> ends with <i>b</i>. The test is 
 * <i>case-insensitive</i> but depends on that all characters
 * in the two strings can be translated in the current locale.
 * @param a The string to search for b in
 * @param b The sub-string to test a against
 * @return true if a ends with b, otherwise false
 */
int Str_endsWith(const char *a, const char *b);


/**
 * Returns the first substring of <i>a</i> that match the string <code>b</code>.
 * If any of the parameters are NULL or <code>b</code> is an empty string, 
 * NULL is returned. The test is <i>case-insensitive</i>.
 * Example:
 * <pre>
 * Str_sub("Haystack with Needle", "needle") -> "Needle"
 * Str_sub("foo bar baz", "bar") -> "bar baz"
 * Str_sub("foo", "foo bar") -> NULL
 * Str_sub("foo", "") -> NULL
 * </pre>
 * @param a The string to search for b in
 * @param b The sub-string to search for in a
 * @return A pointer to the start of the substring in a that contains b, 
 * otherwise NULL
 */
char *Str_sub(const char *a, const char *b);


/**
 * Returns true if <i>s</i> contains any characters in the 
 * <code>charset</code>. Example: 
 * <pre>
 * char *foo = "'bar' (baz)"; 
 * Str_has("(')", foo) -> true
 * Str_has(",;", foo) -> false
 * Str_has(",;", NULL) -> false
 * </pre>
 * @param charset The characters to test <code>s</code> against
 * @param s The string to test
 * @return true if s contains chars in charset, otherwise false
 */
int Str_has(const char *charset, const char *s);


/**
 * Returns true if <i>a</i> equals <i>b</i>. The test is 
 * <i>case-insensitive</i> but depends on that all characters
 * in the two strings can be translated in the current locale.
 * @param a The string to test for equality with <code>b</code>
 * @param b The string to test for equality with <code>a</code>
 * @return true if a equals b, otherwise false
 */
int Str_isEqual(const char *a, const char *b);


/**
 * Returns true if <i>a</i> equals <i>b</i>. The
 * test is <i>case-sensitive</i> and compares byte by byte 
 * @param a The string to test for equality with <code>b</code>
 * @param b The string to test for equality with <code>a</code>
 * @return true if a equals b, otherwise false
 */
int Str_isByteEqual(const char *a, const char *b);


/**
 * Strcpy that copy only <code>n</code> char from the given
 * string. The destination string, <code>dest</code>, is NUL
 * terminated at length <code>n</code> or if <code>src</code> is
 * shorter than <code>n</code> at the length of <code>src</code>
 * @param dest The destination buffer
 * @param src The string to copy to dest
 * @param n The number of bytes to copy
 * @return A pointer to dest
 */
char *Str_copy(char *dest, const char *src, int n);


/**
 * Returns a copy of <code>s</code>. The caller must free the returned String.
 * @param s A String to duplicate
 * @return A pointer to the duplicated string, NULL if s is NULL
 * @exception MemoryException if allocation failed
 */
char *Str_dup(const char *s);


/**
 * Strdup that duplicates only n char from the given string The caller 
 * must free the returned String. If s is shorter than n characters long, 
 * all characters of s are copied. I.e. the same as calling Str_dup(s).
 * @param s A string to duplicate
 * @param n The number of bytes to copy from s
 * @return A pointer to the duplicated string, NULL if s is NULL
 * @exception MemoryException if allocation failed
 * @exception AssertException if n is less than 0
 */
char *Str_ndup(const char *s, long n);


/**
 * Copy <code>n</code> bytes from a variable number of strings. The 
 * destination string, <code>dest</code>, is 0 terminated at length
 * <code>n</code> or if number of bytes to copy is shorter than 
 * <code>n</code> at the combined length of the given strings.
 * Example:
 * <pre>
 * char dest[10 + 1];
 *
 * Str_join(dest, 10, "012", "3456789", "foo") -> "0123456789"
 * Str_join(dest, 4, "a", "b", "cd", "ghi", "jklmnopq") -> "abcd"
 * Str_join(dest, 10) -> ""
 * </pre>
 * <i><small>It is an unchecked runtime error not to provide at least one 
 * parameter in a variable argument list. This macro for the _Str_join()
 * function ensures that at least one parameter exist in the argument list
 * and its last parameter is NULL. </small></i>
 * @param dest The destination buffer
 * @param n The number of bytes to copy
 * @return A pointer to dest
 * @exception AssertException if <code>dest</code> is null
 * @hideinitializer 
 */
#define Str_join(dest, n, ...) _Str_join((dest), (n), ##__VA_ARGS__, 0)
/** Copy n bytes from a variable number of strings. @see Str_join() */
char *_Str_join(char *dest, int n, ...);


/**
 * Creates a new String by merging a formated string and a variable
 * argument list. The caller must free the returned String.
 * @param s A format string
 * @return The new String or NULL if the string could not be created
 * @exception MemoryException if memory allocation fails
 */
char *Str_cat(const char *s, ...) __attribute__((format (printf, 1, 2)));


/**
 * Creates a new String by merging a formated string and a variable
 * argument list. The caller must free the returned String.
 * @param s A format string
 * @param ap A variable argument lists
 * @return a new String concating s and va_list or NULL on error
 * @exception MemoryException if memory allocation fails
 */
char *Str_vcat(const char *s, va_list ap);


/**
 * Truncate <code>s</code> at <code>n</code> and add a trailing ellipsis
 * to the end of <code>s</code>. If <code>s</code> is shorter than 
 * <code>n</code> or has no space for the trail, <code>s</code> is left
 * untouched otherwise this function modifies <code>s</code>. 
 * <pre>
 * Example: 
 *  char s[] = "Hello World!";
 *  Str_trunc(s, strlen(s)); -> "Hello World!" 
 *  Str_trunc(s, 5); -> "Hello..."
 *  Str_trunc(s, 0); -> "..."
 * </pre>
 * @param s String to truncate at n
 * @param n number of bytes from where s is truncated
 * @return A pointer to s
 * @exception AssertException if n is less than 0
*/
char *Str_trunc(char *s, int n);


/**
 * Cut string <code>s</code> short at <code>t</code>. That is, 
 * remove all bytes in <code>s</code> from and including 
 * <code>t</code> to the end of the string. If <code>t</code>
 * is not found in <code>s</code>, <code>s</code> is not modified.
 * <pre>
 * Example: 
 *  char s[] = "<text>Hello World</text>";
 *  Str_curtail(s, "</text>"); -> "<text>Hello World" 
 *  Str_curtail(s, ">"); -> "<text"
 *  Str_curtail(s, "@"); -> "<text"
 * </pre>
 * @param s String to curtail
 * @param t The sub-string to shorten the string <code>s</code> from
 * @return A pointer to s
 */
char *Str_curtail(char *s, char *t);


/**
 * Returns true if the string <code>s</code> has length greater than
 * <code>limit</code>, otherwise false.
 * @param s String to test
 * @param limit The limit in bytes to test s against
 * @return true if <code>s.length > limit</code> otherwise false
 * @exception AssertException if limit is less than 0
 */
int Str_lim(const char *s, int limit);


/**
 * Returns true if the regular expression <code>pattern</code> match
 * the <code>subject</code> string, otherwise false. This function 
 * supports POSIX regular expression for <code>pattern</code>. See
 * re_format(7) for details. For example, to test for a valid email
 * address, 
 * <pre>
 * Str_match("^[^@ ]+@([-a-zA-Z0-9]+\\.)+[a-zA-Z]{2,}$", "foo@bar.baz") -> true
 * </pre>
 * @param pattern the regular expression
 * @param subject the string to match agains pattern
 * @return true if subject match pattern, otherwise false
 * @exception AssertException if pattern is invalid or cannot be 
 * compiled. 
 */
int Str_match(const char *pattern, const char *subject);


/**
 * UNIX ELF hash algorithm. May be used as the <code>hash</code>
 * function in a Table or a Set. 
 * @param x A String
 * @return A hash value for the String
 * @see Table.h and Set.h
 */
unsigned int Str_hash(const void *x);


/**
 * Compare case sensitive two strings. Facade function for strcmp(3)
 * that can be used as the comparison function in a Table or a Set
 * @param x A String
 * @param y A String
 * @return 0 if x and y are equal otherwise a non-zero integer
 * @see Table.h and Set.h
 */
int Str_cmp(const void *x, const void *y);


/**
 * Convert the numeric bytes value to a string representation scaled to
 * human friendly storage unit [B, kB, MB, etc.].
 * @param bytes Byte value to convert
 * @param s A result buffer, must be large enough to hold 10 chars
 * @return A pointer to s
 */
char *Str_bytesToSize(double bytes, char s[10]);

#endif

