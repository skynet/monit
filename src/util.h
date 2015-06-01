/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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


#ifndef MONIT_UTIL_H
#define MONIT_UTIL_H


/**
 *  General purpose utility methods.
 *
 *  @file
 */


/**
 * Replace all occurrences of the sub-string old in the string src
 * with the sub-string new. The method is case sensitive for the
 * sub-strings new and old. The string parameter src must be an
 * allocated string, not a character array.
 * @param src An allocated string reference (e.g. &string)
 * @param old The old sub-string
 * @param new The new sub-string
 * @return src where all occurrences of the old sub-string are
 * replaced with the new sub-string.
 */
char *Util_replaceString(char **src, const char *old, const char *new);


/**
 * Count the number the sub-string word occurs in s.
 * @param s The String to search for word in
 * @param word The sub-string to count in s
 */
int Util_countWords(char *s, const char *word);


/**
 * Exchanges \escape sequences in a string
 * @param buf A string
 */
void Util_handleEscapes(char *buf);


/**
 * Variant of Util_handleEscapes() which only handle \0x00 escape sequences
 * in a string
 * @param buf A string
 * @return The new length of buf
 */
int Util_handle0Escapes(char *buf);


/**
 * Convert a digest buffer to a char string
 * @param digest buffer containing a MD digest
 * @param mdlen digest length
 * @param result buffer to write the result to. Must be at least 41 bytes long.
 */
char *Util_digest2Bytes(unsigned char *digest, int mdlen, MD_T result);


/**
 * Compute SHA1 and MD5 message digests simultaneously for bytes read
 * from STREAM (suitable for stdin, which is not always rewindable).
 * The resulting message digest numbers will be written into the first
 * bytes of resblock buffers.
 * @param stream The stream from where the digests are computed
 * @param sha_resblock The buffer to write the SHA1 result to or NULL to skip the SHA1
 * @param md5_resblock The buffer to write the MD5 result to or NULL to skip the MD5
 * @return false if failed, otherwise true
 */
boolean_t Util_getStreamDigests(FILE *stream, void *sha_resblock, void *md5_resblock);


/**
 * Print MD5 and SHA1 hashes to standard output for given file or standard input
 * @param file The file for which the hashes will be printed or NULL for stdin
 */
void Util_printHash(char *file);


/**
 * Store the checksum of given file in supplied buffer
 * @param file The file for which to compute the checksum
 * @param hashtype The hash type (Hash_Md5 or Hash_Sha1)
 * @param buf The buffer where the result will be stored
 * @param bufsize The size of the buffer
 * @return false if failed, otherwise true
 */
boolean_t Util_getChecksum(char *file, Hash_Type hashtype, char *buf, int bufsize);


/**
 * Get the HMAC-MD5 signature
 * @param data The data to sign
 * @param datalen The length of the data to sign
 * @param key The key used for the signature
 * @param keylen The length of the key
 * @param digest Buffer containing a signature. Must be at least 16 bytes long.
 */
void Util_hmacMD5(const unsigned char *data, int datalen, const unsigned char *key, int keylen, unsigned char *digest);


/**
 * @param name A service name as stated in the config file
 * @return the named service or NULL if not found
 */
Service_T Util_getService(const char *name);


/**
 * @param name A service name as stated in the config file
 * @return true if the service name exist in the
 * servicelist, otherwise false
 */
boolean_t Util_existService(const char *name);


/**
 * Get the length of the service list, that is; the number of services
 * managed by monit
 * @return The number of services monitored
 */
int Util_getNumberOfServices();


/**
 * Print the Runtime object
 */
void Util_printRunList();


/**
 * Print a service object
 * @param p A Service_T object
 */
void Util_printService(Service_T s);


/**
 * Print all the services in the servicelist
 */
void Util_printServiceList();


/**
 * Open and read the id from the given idfile. If the idfile doesn't exist,
 * generate new id and store it in the id file.
 * @param idfile An idfile with full path
 * @return the id or NULL
 */
char *Util_monitId(char *idfile);


/**
 * Open and read the pid from the given pidfile.
 * @param pidfile A pidfile with full path
 * @return the pid or 0 if the pid could
 * not be read from the file
 */
pid_t Util_getPid(char *pidfile);


/**
 * Check whether the process is running
 * @param s The service being checked
 * @param refresh true to refresh the global ptree (useful for procmatch if process was mangled by monit in the same cycle such as by restart action) or false to use cached ptree
 * @return The PID of the running running process or 0 if the process is not running.
 */
int Util_isProcessRunning(Service_T s, boolean_t refresh);


/**
 * Compute an uptime string based on the delta time in seconds. The
 * caller must free the returned string.
 * @param delta seconds.
 * @param sep string separator
 * @return an uptime string
 */
char *Util_getUptime(time_t delta, char *sep);


/**
 * Returns true if url contains url safe characters otherwise false
 * @param url an url string to test
 * @return true if url is url safe otherwise false
 */
boolean_t Util_isurlsafe(const char *url);

/**
 * Escape an url string converting unsafe characters to a hex (%xx)
 * representation.  The caller must free the returned string.
 * @param url an url string
 * @return the escaped string
 */
char *Util_urlEncode(char *url);


/**
 * Unescape an url string. The <code>url</code> parameter is modified
 * by this method.
 * @param url an escaped url string
 * @return A pointer to the unescaped <code>url</code>string
 */
char *Util_urlDecode(char *url);


/**
 * URL escape a service name so it can be safely transfeered over HTTP. In
 * particular any '/' chars in name is encoded. The caller must free the
 * returned string.
 * @param name a service name string to be URL encoded
 * @return the escaped string
 */
char *Util_encodeServiceName(char *name);


/**
 * @return a Basic Authentication Authorization string (RFC 2617),
 * with credentials from the Run object, NULL if credentials are not defined.
 */
char *Util_getBasicAuthHeaderMonit();


/**
 * @return a Basic Authentication Authorization string (RFC 2617),
 * NULL if username is not defined.
 */
char *Util_getBasicAuthHeader(char *username, char *password);


/**
 * Redirect the standard file descriptors to /dev/null and route any
 * error messages to the log file.
 */
void Util_redirectStdFds();


/*
 * Close all filedescriptors except standard. Everything
 * seems to have getdtablesize, so we'll use it here, and back
 * out to use 1024 if getdtablesize not available.
 */

void Util_closeFds();


/*
 * Check if monit does have credentials for this user.  If successful
 * a pointer to the password is returned.
 */

Auth_T Util_getUserCredentials(char *uname);


/**
 * Check if the given password match the registred password for the
 * given username.
 * @param uname Username
 * @param outside The password to test
 * @return true if the passwords match for the given uname otherwise
 * false
 */
boolean_t Util_checkCredentials(char *uname, char *outside);


/**
 * Reset the service information structure
 * @param s A Service_T object
 */
void Util_resetInfo(Service_T s);


/**
 * Are service status data available?
 * @param s The service to test
 * @return true if available otherwise false
 */
boolean_t Util_hasServiceStatus(Service_T s);


/**
 * Construct a HTTP/1.1 Host header utilizing information from the
 * socket. The returned hostBuf is set to "hostname:port" or to the
 * empty string if information is not available or not applicable.
 * @param s A connected socket
 * @param hostBuf the buffer to write the host-header to
 * @param len Length of the hostBuf
 * @return the hostBuffer
 */
char *Util_getHTTPHostHeader(Socket_T s, char *hostBuf, int len);


/**
 * Evaluate a qualification expression.
 * @param operator The qualification operator
 * @param left Expression lval
 * @param rightExpression rval
 * @return the boolean value of the expression
 */
boolean_t Util_evalQExpression(Operator_Type operator, long long left, long long right);


/**
 * Evaluate a qualification expression.
 * @param operator The qualification operator
 * @param left Expression lval
 * @param rightExpression rval
 * @return the boolean value of the expression
 */
boolean_t Util_evalDoubleQExpression(Operator_Type operator, double left, double right);


/*
 * This will enable service monitoring in the case that it was disabled.
 * @param s A Service_T object
 */
void Util_monitorSet(Service_T s);


/*
 * This will disable service monitoring in the case that it is enabled
 * @param s A Service_T object
 */
void Util_monitorUnset(Service_T s);


/*
 * Retun appropriate action id for string
 * @param action A action string
 * @return the action id
 */
int Util_getAction(const char *action);


/*
 * Append full action description to given string buffer
 * @param action An action object
 * @param buf StringBuffer
 * @return StringBuffer reference
 */
StringBuffer_T Util_printAction(Action_T action, StringBuffer_T buf);


/**
 * Append event ratio needed to trigger the action to given string buffer
 * @param action A action string
 * @param buf StringBuffer
 * @return StringBuffer reference
 */
StringBuffer_T Util_printEventratio(Action_T action, StringBuffer_T buf);


/**
 * Append a rule description to the given StringBuffer. The description
 * consists of the formatted string given by the rule argument and constant
 * part which describes rule actions based on the action argument.
 * @param buf StringBuffer
 * @param action An EventAction object
 * @param rule Rule description
 * @return StringBuffer reference
 */
StringBuffer_T Util_printRule(StringBuffer_T buf, EventAction_T action, const char *rule, ...);


/**
 * Print port IP version description
 * @param p A port structure
 * @return the socket IP version description
 */
const char *Util_portIpDescription(Port_T p);


/**
 * Print port type description
 * @param p A port structure
 * @return the socket type description
 */
const char *Util_portTypeDescription(Port_T p);


/**
 * Print port request description
 * @param p A port structure
 * @return the request description
 */
const char *Util_portRequestDescription(Port_T p);


/**
 * Print full port description \[<host>\]:<port>[request][ via TCP|TCPSSL|UDP]
 * @param p A port structure
 * @param buf Buffer
 * @param bufsize Buffer size
 * @return the buffer
 */
char *Util_portDescription(Port_T p, char *buf, int bufsize);


/**
 *  Returns the FQDN hostname or fallback to gethostname() output
 *  @param buf the character array for hostname
 *  @param len the length of buf
 *  @return zero on success
 */
int Util_getfqdnhostname(char *buf, unsigned len);


/**
 * Return string presentation of TIME_* unit
 *  @param time The TIME_* unit (see monit.h)
 *  @return string
 */
const char *Util_timestr(int time);


#endif

