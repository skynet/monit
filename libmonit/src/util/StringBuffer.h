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


#ifndef STRINGBUFFER_INCLUDED
#define STRINGBUFFER_INCLUDED


/** 
 * A <b>StringBuffer</b> implements a mutable sequence of characters. 
 * Indexing starts at 0 and it is a checked runtime error to access 
 * index out of the range.
 *
 * This class is reentrant but not thread-safe
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


#define T StringBuffer_T
typedef struct T *T;


/**
 * Constructs a string buffer so that it represents the same sequence of 
 * characters as the string argument; in other  words, the initial contents 
 * of the string buffer is a copy of the argument string. 
 * @param s the initial contents of the buffer
 * @return A new StringBuffer object
 * @exception MemoryException if allocation failed
 */
T StringBuffer_new(const char *s);


/**
 * Factory method, create an empty string buffer
 * @param hint The initial capacity of the buffer in bytes (hint > 0)
 * @return A new StringBuffer object
 * @exception AssertException if hint is less than or equal to 0
 * @exception MemoryException if allocation failed
 */
T StringBuffer_create(int hint);


/**
 * Destroy a StringBuffer object and free allocated resources
 * @param S a StringBuffer object reference
 */
void StringBuffer_free(T *S);


/**
 * The characters of the String argument are appended, in order, to the 
 * contents of this string buffer, increasing the length of this string 
 * buffer by the length of the argument. 
 * @param S StringBuffer object
 * @param s A string with optional var args
 * @return a reference to this StringBuffer
 * @exception MemoryException if allocation was used and failed
 */
T StringBuffer_append(T S, const char *s, ...) __attribute__((format (printf, 2, 3)));


/**
 * The characters of the String argument are appended, in order, to the 
 * contents of this string buffer, increasing the length of this string 
 * buffer by the length of the arguments. 
 * @param S StringBuffer object
 * @param s A string with optional var args
 * @param ap A variable argument list
 * @return a reference to this StringBuffer
 * @exception MemoryException if allocation was used and failed
 */
T StringBuffer_vappend(T S, const char *s, va_list ap);


/**
 * Returns the character in the given <code>index</code> position. The
 * first char in the string buffer is located at position 0 and the last
 * character is located at StringBuffer_length() - 1. The index parameter
 * must be greater than or equal to 0 and less than the length of the 
 * StringBuffer.
 * @param S StringBuffer object
 * @param index The index of the character to return
 * @return The char located at index
 * @exception AssertException if the index parameter is negative 
 * or greater than or equal to the StringBuffer length.
 */
char StringBuffer_charAt(T S, int index);


/**
 * Set the character in the StringBuffer to <code>c</code> at the 
 * <code>index</code> position. The index parameter must be greater 
 * than or equal to 0 and less than the length of the StringBuffer.
 * @param S StringBuffer object
 * @param index The index of the character to set
 * @param c The character to set
 * @exception AssertException if the index parameter is negative 
 * or greater than or equal to the StringBuffer length.
 */
void StringBuffer_setCharAt(T S, int index, char c);


/**
 * Replace all occurences of <code>a</code> with <code>b</code>. Example: 
 * <pre>
 * StringBuffer_T b = StringBuffer_new("foo bar baz foo foo bar baz"); 
 * StringBuffer_replace(b, "baz", "bar") -> "foo bar bar foo foo bar bar"
 * StringBuffer_replace(b, "foo bar ", "") -> "bar foo bar"
 * </pre>
 * @param S StringBuffer object
 * @param a The sub-string to be replaced with <code>b</code>
 * @param b The string to replace <code>a</code>
 * @return The number of replacements that took place
 * @exception MemoryException if allocation was used and failed
 */
int StringBuffer_replace(T S, const char *a, const char *b);


/**
 * Remove (any) leading and trailing white space [ \\t\\r\\n]. Example
 * <pre>
 * StringBuffer_T b = StringBuffer_new("\t 'foo bar' \n"); 
 * StringBuffer_trim(b) -> "'foo bar'"
 * </pre>
 * @param S StringBuffer object
 * @return a reference to this StringBuffer
 */
T StringBuffer_trim(T S);


/**
 * Remove all characters from the given <code>index</code> position and 
 * to the end of the StringBuffer. The index parameter must be greater 
 * than or equal to 0 and less than the length of the StringBuffer.
 * @param S StringBuffer object
 * @param index The position of the buffer to start truncating
 * @exception AssertException if the index parameter is negative 
 * or greater than or equal to the StringBuffer length.
 * @return a reference to this StringBuffer
 */
T StringBuffer_delete(T S, int index);


/**
 * Locate the first occurrence of the string <code>s</code> 
 * in the StringBuffer. Example:
 * <pre>
 * StringBuffer_T b = StringBuffer_new("foo bar");
 * StringBuffer_indexOf(b, "foo") ->  0
 * StringBuffer_indexOf(b, "bar") ->  4
 * StringBuffer_indexOf(b, "a")   ->  5
 * StringBuffer_indexOf(b, "xy")  -> -1
 * </pre>
 * @param S StringBuffer object
 * @param s The string to search for in the buffer
 * @return The index of the first occurence of <code>s</code> in the
 * buffer or -1 if not found.
 */
int StringBuffer_indexOf(T S, const char *s);


/**
 * Locate the last occurrence of the string <code>s</code> 
 * in the StringBuffer.
 * @param S StringBuffer object
 * @param s The string to search for in the buffer
 * @return The index of the last occurence of <code>s</code> in the
 * buffer or -1 if not found.
 */
int StringBuffer_lastIndexOf(T S, const char *s);


/**
 * Returns a substring of characters currently contained in this character 
 * sequence. The substring begins at the specified index and extends to the
 * end of this sequence
 * @param S StringBuffer object
 * @param index The start index of the substring
 * @return A substring of StringBuffer
 * @exception AssertException if the index parameter is negative 
 * or greater than or equal to the StringBuffer length.
 */
const char *StringBuffer_substring(T S, int index);


/**
 * Returns the length (character count) of this string buffer <i>not 
 * including the last '\\0' char used to terminate a C-string</i>.
 * @param S StringBuffer object
 * @return the length of the sequence of characters currently represented 
 * by this string buffer <i>not including the last NUL character</i>.
 */
int StringBuffer_length(T S);


/**
 * Clears the contents of the string buffer and set buffer length to 0.
 * @param S StringBuffer object
 * @return a reference to this StringBuffer
 */
T StringBuffer_clear(T S);


/**
 * Returns a string representing the data in this string buffer.
 * @param S StringBuffer object
 * @return a string representation of the string buffer 
 */
const char *StringBuffer_toString(T S);


#undef T
#endif
