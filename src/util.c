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

#include "config.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_PAM_PAM_APPL_H
#include <pam/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#include "monit.h"
#include "engine.h"
#include "md5.h"
#include "md5_crypt.h"
#include "sha1.h"
#include "base64.h"
#include "alert.h"
#include "process.h"
#include "event.h"
#include "state.h"


struct ad_user {
        const char *login;
        const char *passwd;
};


/* Unsafe URL characters: <>\"#%{}|\\^[] ` */
static const unsigned char urlunsafe[256] = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};


static const unsigned char b2x[][256] = {
        "00", "01", "02", "03", "04", "05", "06", "07",
        "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
        "10", "11", "12", "13", "14", "15", "16", "17",
        "18", "19", "1A", "1B", "1C", "1D", "1E", "1F",
        "20", "21", "22", "23", "24", "25", "26", "27",
        "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
        "30", "31", "32", "33", "34", "35", "36", "37",
        "38", "39", "3A", "3B", "3C", "3D", "3E", "3F",
        "40", "41", "42", "43", "44", "45", "46", "47",
        "48", "49", "4A", "4B", "4C", "4D", "4E", "4F",
        "50", "51", "52", "53", "54", "55", "56", "57",
        "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
        "60", "61", "62", "63", "64", "65", "66", "67",
        "68", "69", "6A", "6B", "6C", "6D", "6E", "6F",
        "70", "71", "72", "73", "74", "75", "76", "77",
        "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",
        "80", "81", "82", "83", "84", "85", "86", "87",
        "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
        "90", "91", "92", "93", "94", "95", "96", "97",
        "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",
        "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7",
        "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",
        "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7",
        "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
        "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7",
        "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",
        "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7",
        "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",
        "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7",
        "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
        "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7",
        "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"
};


/**
 *  General purpose utility methods.
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


/**
 * Returns the value of the parameter if defined or the String "(not
 * defined)"
 */
static char *is_str_defined(char *s) {
        return((s && *s) ? s : "(not defined)");
}


/**
 * Convert a hex char to a char
 */
static char x2c(char *hex) {
        register char digit;
        digit = ((hex[0] >= 'A') ? ((hex[0] & 0xdf) - 'A')+10 : (hex[0] - '0'));
        digit *= 16;
        digit += (hex[1] >= 'A' ? ((hex[1] & 0xdf) - 'A')+10 : (hex[1] - '0'));
        return(digit);
}


/**
 * Print registered events list
 */
static void printevents(unsigned int events) {
        if (events == Event_Null) {
                printf("No events");
        } else if (events == Event_All) {
                printf("All events");
        } else {
                if (IS_EVENT_SET(events, Event_Action))
                        printf("Action ");
                if (IS_EVENT_SET(events, Event_Checksum))
                        printf("Checksum ");
                if (IS_EVENT_SET(events, Event_Connection))
                        printf("Connection ");
                if (IS_EVENT_SET(events, Event_Content))
                        printf("Content ");
                if (IS_EVENT_SET(events, Event_Data))
                        printf("Data ");
                if (IS_EVENT_SET(events, Event_Exec))
                        printf("Exec ");
                if (IS_EVENT_SET(events, Event_Fsflag))
                        printf("Fsflags ");
                if (IS_EVENT_SET(events, Event_Gid))
                        printf("Gid ");
                if (IS_EVENT_SET(events, Event_Icmp))
                        printf("Icmp ");
                if (IS_EVENT_SET(events, Event_Instance))
                        printf("Instance ");
                if (IS_EVENT_SET(events, Event_Invalid))
                        printf("Invalid ");
                if (IS_EVENT_SET(events, Event_Nonexist))
                        printf("Nonexist ");
                if (IS_EVENT_SET(events, Event_Permission))
                        printf("Permission ");
                if (IS_EVENT_SET(events, Event_Pid))
                        printf("PID ");
                if (IS_EVENT_SET(events, Event_PPid))
                        printf("PPID ");
                if (IS_EVENT_SET(events, Event_Resource))
                        printf("Resource ");
                if (IS_EVENT_SET(events, Event_Size))
                        printf("Size ");
                if (IS_EVENT_SET(events, Event_Status))
                        printf("Status ");
                if (IS_EVENT_SET(events, Event_Timeout))
                        printf("Timeout ");
                if (IS_EVENT_SET(events, Event_Timestamp))
                        printf("Timestamp ");
                if (IS_EVENT_SET(events, Event_Uid))
                        printf("Uid ");
                if (IS_EVENT_SET(events, Event_Uptime))
                        printf("Uptime ");

        }
        printf("\n");
}


#ifdef HAVE_LIBPAM
/**
 * PAM conversation
 */
#if defined(SOLARIS) || defined(AIX)
static int PAMquery(int num_msg, struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
#else
static int PAMquery(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
#endif
        int i;
        struct ad_user *user = (struct ad_user *)appdata_ptr;
        struct pam_response *response;

        /* Sanity checking */
        if (!msg || !resp || !user )
                return PAM_CONV_ERR;

        response = CALLOC(sizeof(struct pam_response), num_msg);

        for (i = 0; i < num_msg; i++) {
                response[i].resp = NULL;
                response[i].resp_retcode = 0;

                switch ((*(msg[i])).msg_style) {
                        case PAM_PROMPT_ECHO_ON:
                                /* Store the login as the response. This likely never gets called, since login was on pam_start() */
                                response[i].resp = appdata_ptr ? Str_dup(user->login) : NULL;
                                break;

                        case PAM_PROMPT_ECHO_OFF:
                                /* Store the password as the response */
                                response[i].resp = appdata_ptr ? Str_dup(user->passwd) : NULL;
                                break;

                        case PAM_TEXT_INFO:
                        case PAM_ERROR_MSG:
                                /* Shouldn't happen since we have PAM_SILENT set. If it happens anyway, ignore it. */
                                break;

                        default:
                                /* Something strange... */
                                if (response != NULL)
                                        FREE(response);
                                return PAM_CONV_ERR;
                }
        }
        /* On success, return the response structure */
        *resp = response;
        return PAM_SUCCESS;
}


/**
 * Validate login/passwd via PAM service "monit"
 */
static int PAMcheckPasswd(const char *login, const char *passwd) {
        int rv;
        pam_handle_t *pamh = NULL;
        struct ad_user user_info = {
                login,
                passwd
        };
        struct pam_conv conv = {
                PAMquery,
                &user_info
        };

        if ((rv = pam_start("monit", login, &conv, &pamh) != PAM_SUCCESS)) {
                DEBUG("PAM authentication start failed -- %d\n", rv);
                return FALSE;
        }

        rv = pam_authenticate(pamh, PAM_SILENT);

        if (pam_end(pamh, rv) != PAM_SUCCESS)
                pamh = NULL;

        return(rv == PAM_SUCCESS ? TRUE : FALSE);
}


/**
 * Check whether the user is member of allowed groups
 */
static Auth_T PAMcheckUserGroup(const char *uname) {
        Auth_T c = Run.credentials;
        struct passwd *pwd = NULL;
        struct group  *grp = NULL;

        ASSERT(uname);

        if (!(pwd = getpwnam(uname)))
                return NULL;

        if (!(grp = getgrgid(pwd->pw_gid)))
                return NULL;

        while (c) {
                if (c->groupname) {
                        struct group *sgrp = NULL;

                        /* check for primary group match */
                        if (IS(c->groupname, grp->gr_name))
                                return c;

                        /* check secondary groups match */
                        if ((sgrp = getgrnam(c->groupname))) {
                                char **g = NULL;

                                for (g = sgrp->gr_mem; *g; g++)
                                        if (IS(*g, uname))
                                                return c;
                        }
                }
                c = c->next;
        }
        return NULL;
}
#endif


/* ------------------------------------------------------------------ Public */


char *Util_replaceString(char **src, const char *old, const char *new) {
        int i;
        size_t d;

        ASSERT(src);
        ASSERT(*src);
        ASSERT(old);
        ASSERT(new);

        i = Util_countWords(*src, old);
        d = strlen(new)-strlen(old);

        if (i==0)
                return *src;
        if (d>0)
                d*= i;
        else
                d = 0;

        {
                char *p, *q;
                size_t l = strlen(old);
                char *buf = CALLOC(sizeof(char), strlen(*src)+d+1);

                q = *src;
                *buf = 0;

                while((p = strstr(q, old))) {

                        *p = '\0';
                        strcat(buf, q);
                        strcat(buf, new);
                        p+= l;
                        q = p;

                }

                strcat(buf, q);
                FREE(*src);
                *src = buf;
        }
        return *src;
}


int Util_countWords(char *s, const char *word) {
        int i = 0;
        char *p = s;

        ASSERT(s && word);

        while((p = strstr(p, word))) { i++;  p++; }
        return i;
}


void Util_handleEscapes(char *buf) {
        int editpos;
        int insertpos;

        ASSERT(buf);

        for (editpos=insertpos=0; *(buf+editpos)!='\0'; editpos++, insertpos++) {
                if (*(buf+editpos) == '\\' ) {
                        switch (*(buf+editpos+1)) {
                                case 'n':
                                        *(buf+insertpos)='\n';
                                        editpos++;
                                        break;

                                case 't':
                                        *(buf+insertpos)='\t';
                                        editpos++;
                                        break;

                                case 'r':
                                        *(buf+insertpos)='\r';
                                        editpos++;
                                        break;

                                case ' ':
                                        *(buf+insertpos)=' ';
                                        editpos++;
                                        break;

                                case '0':
                                        if (*(buf+editpos+2)=='x') {
                                                if ((*(buf+editpos+3)=='0' && *(buf+editpos+4)=='0')) {
                                                        /* Don't swap \0x00 with 0 to avoid truncating the string.
                                                         Currently the only place where we support sending of 0 bytes
                                                         is in check_generic(). The \0x00 -> 0 byte swap is performed
                                                         there and in-place.
                                                         */
                                                        *(buf+insertpos)=*(buf+editpos);
                                                } else {
                                                        *(buf+insertpos)=x2c(&buf[editpos+3]);
                                                        editpos+=4;
                                                }
                                        }
                                        break;

                                case '\\':
                                        *(buf+insertpos)='\\';
                                        editpos++;
                                        break;

                                default:
                                        *(buf+insertpos)=*(buf+editpos);

                        }

                } else {
                        *(buf+insertpos)=*(buf+editpos);
                }

        }
        *(buf+insertpos)='\0';
}


int Util_handle0Escapes(char *buf) {
        int editpos;
        int insertpos;

        ASSERT(buf);

        for (editpos=insertpos=0; *(buf+editpos)!='\0'; editpos++, insertpos++) {
                if (*(buf+editpos) == '\\' ) {
                        switch (*(buf+editpos+1)) {
                                case '0':
                                        if (*(buf+editpos+2)=='x') {
                                                *(buf+insertpos)=x2c(&buf[editpos+3]);
                                                editpos+=4;
                                        }
                                        break;

                                default:
                                        *(buf+insertpos)=*(buf+editpos);

                        }

                } else {
                        *(buf+insertpos)=*(buf+editpos);
                }
        }
        *(buf+insertpos)='\0';
        return insertpos;
}


char *Util_digest2Bytes(unsigned char *digest, int mdlen, MD_T result) {
        int i;
        unsigned char *tmp = (unsigned char*)result;
        static unsigned char hex[] = "0123456789abcdef";
        ASSERT(mdlen * 2 < MD_SIZE); // Overflow guard
        for (i = 0; i < mdlen; i++) {
                *tmp++ = hex[digest[i] >> 4];
                *tmp++ = hex[digest[i] & 0xf];
        }
        *tmp = '\0';
        return result;
}


int Util_getStreamDigests(FILE *stream, void *sha1_resblock, void *md5_resblock) {
#define HASHBLOCKSIZE 4096
        md5_context_t ctx_md5;
        sha1_context_t ctx_sha1;
        unsigned char buffer[HASHBLOCKSIZE + 72];
        size_t sum;

        /* Initialize the computation contexts */
        if (md5_resblock)
                md5_init(&ctx_md5);
        if (sha1_resblock)
                sha1_init(&ctx_sha1);

        /* Iterate over full file contents */
        while (1)  {
                /* We read the file in blocks of HASHBLOCKSIZE bytes. One call of the computation function processes the whole buffer so that with the next round of the loop another block can be read */
                size_t n;
                sum = 0;

                /* Read block. Take care for partial reads */
                while (1) {
                        n = fread(buffer + sum, 1, HASHBLOCKSIZE - sum, stream);
                        sum += n;
                        if (sum == HASHBLOCKSIZE)
                                break;
                        if (n == 0) {
                                /* Check for the error flag IFF N == 0, so that we don't exit the loop after a partial read due to e.g., EAGAIN or EWOULDBLOCK */
                                if (ferror(stream))
                                        return FALSE;
                                goto process_partial_block;
                        }

                        /* We've read at least one byte, so ignore errors. But always check for EOF, since feof may be true even though N > 0. Otherwise, we could end up calling fread after EOF */
                        if (feof(stream))
                                goto process_partial_block;
                }

                /* Process buffer with HASHBLOCKSIZE bytes. Note that HASHBLOCKSIZE % 64 == 0 */
                if (md5_resblock)
                        md5_append(&ctx_md5, (const md5_byte_t *)buffer, HASHBLOCKSIZE);
                if (sha1_resblock)
                        sha1_append(&ctx_sha1, buffer, HASHBLOCKSIZE);
        }

process_partial_block:
        /* Process any remaining bytes */
        if (sum > 0) {
                if (md5_resblock)
                        md5_append(&ctx_md5, (const md5_byte_t *)buffer, (int)sum);
                if (sha1_resblock)
                        sha1_append(&ctx_sha1, buffer, sum);
        }
        /* Construct result in desired memory */
        if (md5_resblock)
                md5_finish(&ctx_md5, md5_resblock);
        if (sha1_resblock)
                sha1_finish(&ctx_sha1, sha1_resblock);
        return TRUE;
}


void Util_printHash(char *file) {
        MD_T hash;
        unsigned char sha1[STRLEN], md5[STRLEN];
        FILE *fhandle = NULL;

        if (! (fhandle = file ? fopen(file, "r") : stdin) || ! Util_getStreamDigests(fhandle, sha1, md5) || (file && fclose(fhandle))) {
                printf("%s: %s\n", file, STRERROR);
                exit(1);
        }
        printf("SHA1(%s) = %s\n", file ? file : "stdin", Util_digest2Bytes(sha1, 20, hash));
        printf("MD5(%s)  = %s\n", file ? file : "stdin", Util_digest2Bytes(md5, 16, hash));
}


int Util_getChecksum(char *file, int hashtype, char *buf, int bufsize) {
        int hashlength = 16;

        ASSERT(file);
        ASSERT(buf);
        ASSERT(bufsize >= sizeof(MD_T));

        switch (hashtype) {
                case HASH_MD5:
                        hashlength = 16;
                        break;
                case HASH_SHA1:
                        hashlength = 20;
                        break;
                default:
                        LogError("checksum: invalid hash type: 0x%x\n", hashtype);
                        return FALSE;
        }

        if (file_isFile(file)) {
                FILE *f = fopen(file, "r");
                if (f) {
                        int fresult = FALSE;
                        MD_T sum;

                        switch (hashtype) {
                                case HASH_MD5:
                                        fresult = Util_getStreamDigests(f, NULL, sum);
                                        break;
                                case HASH_SHA1:
                                        fresult = Util_getStreamDigests(f, sum, NULL);
                                        break;
                        }

                        if (fclose(f))
                                LogError("checksum: error closing file '%s' -- %s\n", file, STRERROR);

                        if (! fresult) {
                                LogError("checksum: file %s stream error (0x%x)\n", file, fresult);
                                return FALSE;
                        }

                        Util_digest2Bytes((unsigned char *)sum, hashlength, buf);
                        return TRUE;

                } else
                        LogError("checksum: failed to open file %s -- %s\n", file, STRERROR);
        } else
                LogError("checksum: file %s is not regular file\n", file);
        return FALSE;
}


void Util_hmacMD5(const unsigned char *data, int datalen, const unsigned char *key, int keylen, unsigned char *digest) {
        md5_context_t ctx;
        md5_init(&ctx);
        unsigned char k_ipad[65];
        unsigned char k_opad[65];
        unsigned char tk[16];
        int i;

        if (keylen > 64) {
                md5_context_t tctx;
                md5_init(&tctx);
                md5_append(&tctx, (const md5_byte_t *)key, keylen);
                md5_finish(&tctx, tk);
                key = tk;
                keylen = 16;
        }

        memset(k_ipad, 0, sizeof(k_ipad));
        memset(k_opad, 0, sizeof(k_opad));
        memcpy(k_ipad, key, keylen);
        memcpy(k_opad, key, keylen);

        for (i = 0; i < 64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }

        md5_init(&ctx);
        md5_append(&ctx, (const md5_byte_t *)k_ipad, 64);
        md5_append(&ctx, (const md5_byte_t *)data, datalen);
        md5_finish(&ctx, digest);

        md5_init(&ctx);
        md5_append(&ctx, (const md5_byte_t *)k_opad, 64);
        md5_append(&ctx, (const md5_byte_t *)digest, 16);
        md5_finish(&ctx, digest);
}


Service_T Util_getService(const char *name) {
        Service_T s;

        ASSERT(name);

        for (s = servicelist; s; s = s->next) {
                if (IS(s->name, name)) {
                        return s;
                }
        }
        return NULL;
}


int Util_getNumberOfServices() {
        int i = 0;
        Service_T s;
        for (s = servicelist; s; s = s->next) i+=1;
        return i;
}


int Util_existService(const char *name) {
        ASSERT(name);
        return Util_getService(name)?TRUE:FALSE;
}


void Util_printRunList() {
        printf("Runtime constants:\n");
        printf(" %-18s = %s\n", "Control file", is_str_defined(Run.controlfile));
        printf(" %-18s = %s\n", "Log file", is_str_defined(Run.logfile));
        printf(" %-18s = %s\n", "Pid file", is_str_defined(Run.pidfile));
        printf(" %-18s = %s\n", "Id file", is_str_defined(Run.idfile));
        printf(" %-18s = %s\n", "State file", is_str_defined(Run.statefile));
        printf(" %-18s = %s\n", "Debug", Run.debug?"True":"False");
        printf(" %-18s = %s\n", "Log", Run.dolog?"True":"False");
        printf(" %-18s = %s\n", "Use syslog", Run.use_syslog?"True":"False");
        printf(" %-18s = %s\n", "Is Daemon", Run.isdaemon?"True":"False");
        printf(" %-18s = %s\n", "Use process engine", Run.doprocess?"True":"False");
        printf(" %-18s = %d seconds with start delay %d seconds\n", "Poll time", Run.polltime, Run.startdelay);
        printf(" %-18s = %d bytes\n", "Expect buffer", Run.expectbuffer);

        if (Run.eventlist_dir) {
                char slots[STRLEN];

                if (Run.eventlist_slots < 0)
                        snprintf(slots, STRLEN, "unlimited");
                else
                        snprintf(slots, STRLEN, "%d", Run.eventlist_slots);

                printf(" %-18s = base directory %s with %s slots\n",
                       "Event queue", Run.eventlist_dir, slots);
        }

        if (Run.mmonits) {
                Mmonit_T c;
                printf(" %-18s = ", "M/Monit(s)");
                for (c = Run.mmonits; c; c = c->next) {
                        printf("%s with timeout %d seconds%s%s%s%s%s%s",
                               c->url->url,
                               c->timeout,
                               (c->ssl.use_ssl && c->ssl.version) ? " ssl version " : "",
                               (c->ssl.use_ssl && c->ssl.version) ? sslnames[c->ssl.version] : "",
                               c->ssl.certmd5?" server cert md5 sum ":"",
                               c->ssl.certmd5?c->ssl.certmd5:"",
                               c->url->user?" using credentials":"",
                               c->next?",\n                    = ":"");
                }
                if (! Run.dommonitcredentials)
                        printf("\n                      register without credentials");
                printf("\n");
        }

        if (Run.mailservers) {
                MailServer_T mta;
                printf(" %-18s = ", "Mail server(s)");
                for (mta = Run.mailservers; mta; mta = mta->next)
                        printf("%s:%d%s%s",
                               mta->host,
                               mta->port,
                               mta->ssl.use_ssl?"(ssl)":"",
                               mta->next?", ":" ");
                printf("with timeout %d seconds", Run.mailserver_timeout/1000);
                if (Run.mail_hostname)
                        printf(" using '%s' as my hostname", Run.mail_hostname);
                printf("\n");
        }

        printf(" %-18s = %s\n", "Mail from", is_str_defined(Run.MailFormat.from));
        printf(" %-18s = %s\n", "Mail subject",
               is_str_defined(Run.MailFormat.subject));
        printf(" %-18s = %-.20s%s\n", "Mail message",
               Run.MailFormat.message?
               Run.MailFormat.message:"(not defined)",
               Run.MailFormat.message?"..(truncated)":"");

        printf(" %-18s = %s\n", "Start monit httpd", Run.dohttpd?"True":"False");

        if (Run.dohttpd) {

                printf(" %-18s = %s\n", "httpd bind address",
                       Run.bind_addr?Run.bind_addr:"Any/All");
                printf(" %-18s = %d\n", "httpd portnumber", Run.httpdport);
                printf(" %-18s = %s\n", "httpd signature", Run.httpdsig?"True":"False");
                printf(" %-18s = %s\n", "Use ssl encryption", Run.httpdssl?"True":"False");

                if (Run.httpdssl) {

                        printf(" %-18s = %s\n", "PEM key/cert file", Run.httpsslpem);

                        if (Run.httpsslclientpem!=NULL) {
                                printf(" %-18s = %s\n", "Client cert file", Run.httpsslclientpem);
                        } else {
                                printf(" %-18s = %s\n", "Client cert file", "None");
                        }

                        printf(" %-18s = %s\n", "Allow self certs",
                               Run.allowselfcert?"True":"False");

                }

                printf(" %-18s = %s\n", "httpd auth. style",
                       (Run.credentials!=NULL)&&has_hosts_allow()?
                       "Basic Authentication and Host/Net allow list":
                       (Run.credentials!=NULL)?"Basic Authentication":
                       has_hosts_allow()?"Host/Net allow list":
                       "No authentication!");

        }

        {
                Mail_T list;
                for (list = Run.maillist; list; list = list->next) {
                        printf(" %-18s = %s\n", "Alert mail to", is_str_defined(list->to));
                        printf("   %-16s = ", "Alert on");
                        printevents(list->events);
                        if (list->reminder)
                                printf("   %-16s = %u cycles\n", "Alert reminder", list->reminder);
                }
        }

        printf("\n");
}


void Util_printService(Service_T s) {
        ASSERT(s);

        int sgheader = FALSE;
        char buffer[STRLEN];
        StringBuffer_T buf = StringBuffer_create(STRLEN);

        printf("%-21s = %s\n", StringBuffer_toString(StringBuffer_append(buf, "%s Name", servicetypes[s->type])), s->name);

        for (ServiceGroup_T o = servicegrouplist; o; o = o->next) {
                for (ServiceGroupMember_T om = o->members; om; om = om->next) {
                        if (! strcasecmp(om->name, s->name)) {
                                if (! sgheader) {
                                        printf(" %-20s = %s", "Group", o->name);
                                        sgheader = TRUE;
                                } else
                                        printf(", %s", o->name);
                        }
                }
        }
        if (sgheader)
                printf("\n");

        if (s->type == TYPE_PROCESS) {
                if (s->matchlist)
                        printf(" %-20s = %s\n", "Match", s->path);
                else
                        printf(" %-20s = %s\n", "Pid file", s->path);
        } else if (s->type == TYPE_HOST) {
                printf(" %-20s = %s\n", "Address", s->path);
        } else if (s->type != TYPE_SYSTEM) {
                printf(" %-20s = %s\n", "Path", s->path);
        }
        printf(" %-20s = %s\n", "Monitoring mode", modenames[s->mode]);
        if (s->start) {
                printf(" %-20s = '", "Start program");
                for (int i = 0; s->start->arg[i]; i++)
                        printf("%s%s", i ? " " : "", s->start->arg[i]);
                printf("'");
                if (s->start->has_uid)
                        printf(" as uid %d", s->start->uid);
                if (s->start->has_gid)
                        printf(" as gid %d", s->start->gid);
                printf(" timeout %d second(s)", s->start->timeout);
                printf("\n");
        }
        if (s->stop) {
                printf(" %-20s = '", "Stop program");
                for (int i = 0; s->stop->arg[i]; i++)
                        printf("%s%s", i ? " " : "", s->stop->arg[i]);
                printf("'");
                if (s->stop->has_uid)
                        printf(" as uid %d", s->stop->uid);
                if (s->stop->has_gid)
                        printf(" as gid %d", s->stop->gid);
                printf(" timeout %d second(s)", s->stop->timeout);
                printf("\n");
        }
        if (s->restart) {
                printf(" %-20s = '", "Restart program");
                for (int i = 0; s->restart->arg[i]; i++)
                        printf("%s%s", i ? " " : "", s->restart->arg[i]);
                printf("'");
                if (s->restart->has_uid)
                        printf(" as uid %d", s->restart->uid);
                if (s->restart->has_gid)
                        printf(" as gid %d", s->restart->gid);
                printf(" timeout %d second(s)", s->restart->timeout);
                printf("\n");
        }
        if (s->type != TYPE_SYSTEM && s->type != TYPE_PROGRAM) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Existence", StringBuffer_toString(Util_printRule(buf, s->action_NONEXIST, "if does not exist")));
        }

        for (Dependant_T o = s->dependantlist; o; o = o->next)
                if (o->dependant != NULL)
                        printf(" %-20s = %s\n", "Depends on Service", o->dependant);

        if (s->type == TYPE_PROCESS) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Pid", StringBuffer_toString(Util_printRule(buf, s->action_PID, "if changed")));
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "PPid", StringBuffer_toString(Util_printRule(buf, s->action_PPID, "if changed")));
        }

        if (s->type == TYPE_FILESYSTEM) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Filesystem flags", StringBuffer_toString(Util_printRule(buf, s->action_FSFLAG, "if changed")));
        }

        if (s->type == TYPE_PROGRAM) {
                printf(" %-20s = ", "Program timeout");
                printf("terminate the program if not finished within %d seconds\n", s->program->timeout);
                for (Status_T o = s->statuslist; o; o = o->next) {
                        StringBuffer_clear(buf);
                        if (o->operator == Operator_Changed)
                                printf(" %-20s = %s\n", "Status", StringBuffer_toString(Util_printRule(buf, o->action, "if exit value changed")));
                        else
                                printf(" %-20s = %s\n", "Status", StringBuffer_toString(Util_printRule(buf, o->action, "if exit value %s %d", operatorshortnames[o->operator], o->return_value)));
                }
        }

        if (s->checksum && s->checksum->action) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Checksum",
                        s->checksum->test_changes
                        ?
                        StringBuffer_toString(Util_printRule(buf, s->checksum->action, "if changed %s", checksumnames[s->checksum->type]))
                        :
                        StringBuffer_toString(Util_printRule(buf, s->checksum->action, "if failed %s(%s)", s->checksum->hash, checksumnames[s->checksum->type]))
                );
        }

        if (s->perm && s->perm->action) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Permission", StringBuffer_toString(Util_printRule(buf, s->perm->action, "if failed %04o", s->perm->perm)));
        }

        if (s->uid && s->uid->action) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "UID", StringBuffer_toString(Util_printRule(buf, s->uid->action, "if failed %d", s->uid->uid)));
        }

        if (s->euid && s->euid->action) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "EUID", StringBuffer_toString(Util_printRule(buf, s->euid->action, "if failed %d", s->euid->uid)));
        }

        if (s->gid && s->gid->action) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "GID", StringBuffer_toString(Util_printRule(buf, s->gid->action, "if failed %d", s->gid->gid)));
        }

        for (Icmp_T o = s->icmplist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Ping", StringBuffer_toString(Util_printRule(buf, o->action, "if failed [%s count %d with timeout %d seconds]", icmpnames[o->type], o->count, o->timeout)));
        }

        for (Port_T o = s->portlist; o; o = o->next) {
                StringBuffer_clear(buf);
                if (o->family == AF_INET) {
                        if (o->retry > 1)
                                printf(" %-20s = %s\n", "Port", StringBuffer_toString(Util_printRule(buf, o->action, "if failed [%s:%d%s [%s via %s] with timeout %d seconds and retry %d times]", o->hostname, o->port, o->request ? o->request : "", o->protocol->name, Util_portTypeDescription(o), o->timeout, o->retry)));
                        else
                                printf(" %-20s = %s\n", "Port", StringBuffer_toString(Util_printRule(buf, o->action, "if failed [%s:%d%s [%s via %s] with timeout %d seconds]", o->hostname, o->port, o->request ? o->request : "", o->protocol->name, Util_portTypeDescription(o), o->timeout)));
                        if (o->SSL.certmd5 != NULL)
                                printf(" %-20s = %s\n", "Server cert md5 sum", o->SSL.certmd5);
                } else if (o->family == AF_UNIX) {
                        if (o->retry > 1)
                                printf(" %-20s = %s\n", "Unix Socket", StringBuffer_toString(Util_printRule(buf, o->action, "if failed [%s [protocol %s] with timeout %d seconds and retry %d times]", o->pathname, o->protocol->name, o->timeout, o->retry)));
                        else
                                printf(" %-20s = %s\n", "Unix Socket", StringBuffer_toString(Util_printRule(buf, o->action, "if failed [%s [protocol %s] with timeout %d seconds]", o->pathname, o->protocol->name, o->timeout, o->retry)));
                }
        }

        for (Timestamp_T o = s->timestamplist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Timestamp",
                        o->test_changes
                        ?
                        StringBuffer_toString(Util_printRule(buf, o->action, "if changed"))
                        :
                        StringBuffer_toString(Util_printRule(buf, o->action, "if %s %d second(s)", operatornames[o->operator], o->time))
                );
        }

        for (Size_T o = s->sizelist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Size",
                        o->test_changes
                        ?
                        StringBuffer_toString(Util_printRule(buf, o->action, "if changed"))
                        :
                        StringBuffer_toString(Util_printRule(buf, o->action, "if %s %llu byte(s)", operatornames[o->operator], o->size))
                );
        }

        for (Uptime_T o = s->uptimelist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Uptime", StringBuffer_toString(Util_printRule(buf, o->action, "if %s %llu second(s)", operatornames[o->operator], o->uptime)));
        }

        if (s->type != TYPE_PROCESS) {
                for (Match_T o = s->matchignorelist; o; o = o->next) {
                        StringBuffer_clear(buf);
                        printf(" %-20s = %s\n", "Ignore pattern", StringBuffer_toString(Util_printRule(buf, o->action, "if%s match \"%s\"", o->not ? " not" : "", o->match_string)));
                }
                for (Match_T o = s->matchlist; o; o = o->next) {
                        StringBuffer_clear(buf);
                        printf(" %-20s = %s\n", "Pattern", StringBuffer_toString(Util_printRule(buf, o->action, "if%s match \"%s\"", o->not ? " not" : "", o->match_string)));
                }
        }

        for (Filesystem_T o = s->filesystemlist; o; o = o->next) {
                StringBuffer_clear(buf);
                if (o->resource == RESOURCE_ID_INODE) {
                        printf(" %-20s = %s\n", "Inodes usage limit",
                                o->limit_absolute > -1
                                ?
                                StringBuffer_toString(Util_printRule(buf, o->action, "if %s %lld", operatornames[o->operator], o->limit_absolute))
                                :
                                StringBuffer_toString(Util_printRule(buf, o->action, "if %s %.1f%%", operatornames[o->operator], o->limit_percent / 10.))
                        );
                } else if (o->resource == RESOURCE_ID_SPACE) {
                        printf(" %-20s = %s\n", "Space usage limit",
                                o->limit_absolute > -1
                                ?
                                StringBuffer_toString(Util_printRule(buf, o->action, "if %s %lld blocks", operatornames[o->operator], o->limit_absolute))
                                :
                                StringBuffer_toString(Util_printRule(buf, o->action, "if %s %.1f%%", operatornames[o->operator], o->limit_percent / 10.))
                        );
                }
        }

        for (Resource_T o = s->resourcelist; o; o = o->next) {
                StringBuffer_clear(buf);
                switch (o->resource_id) {
                        case RESOURCE_ID_CPU_PERCENT:
                                printf(" %-20s = ", "CPU usage limit");
                                break;

                        case RESOURCE_ID_TOTAL_CPU_PERCENT:
                                printf(" %-20s = ", "CPU usage limit (incl. children)");
                                break;

                        case RESOURCE_ID_CPUUSER:
                                printf(" %-20s = ", "CPU user limit");
                                break;

                        case RESOURCE_ID_CPUSYSTEM:
                                printf(" %-20s = ", "CPU system limit");
                                break;

                        case RESOURCE_ID_CPUWAIT:
                                printf(" %-20s = ", "CPU wait limit");
                                break;

                        case RESOURCE_ID_MEM_PERCENT:
                                printf(" %-20s = ", "Memory usage limit");
                                break;

                        case RESOURCE_ID_MEM_KBYTE:
                                printf(" %-20s = ", "Memory amount limit");
                                break;

                        case RESOURCE_ID_SWAP_PERCENT:
                                printf(" %-20s = ", "Swap usage limit");
                                break;

                        case RESOURCE_ID_SWAP_KBYTE:
                                printf(" %-20s = ", "Swap amount limit");
                                break;

                        case RESOURCE_ID_LOAD1:
                                printf(" %-20s = ", "Load avg. (1min)");
                                break;

                        case RESOURCE_ID_LOAD5:
                                printf(" %-20s = ", "Load avg. (5min)");
                                break;

                        case RESOURCE_ID_LOAD15:
                                printf(" %-20s = ", "Load avg. (15min)");
                                break;

                        case RESOURCE_ID_CHILDREN:
                                printf(" %-20s = ", "Children");
                                break;

                        case RESOURCE_ID_TOTAL_MEM_KBYTE:
                                printf(" %-20s = ", "Memory amount limit (incl. children)");
                                break;

                        case RESOURCE_ID_TOTAL_MEM_PERCENT:
                                printf(" %-20s = ", "Memory usage limit (incl. children)");
                                break;
                }
                switch (o->resource_id) {
                        case RESOURCE_ID_CPU_PERCENT:
                        case RESOURCE_ID_TOTAL_CPU_PERCENT:
                        case RESOURCE_ID_TOTAL_MEM_PERCENT:
                        case RESOURCE_ID_CPUUSER:
                        case RESOURCE_ID_CPUSYSTEM:
                        case RESOURCE_ID_CPUWAIT:
                        case RESOURCE_ID_MEM_PERCENT:
                        case RESOURCE_ID_SWAP_PERCENT:
                                printf("%s", StringBuffer_toString(Util_printRule(buf, o->action, "if %s %.1f%%", operatornames[o->operator], o->limit / 10.0)));
                                break;

                        case RESOURCE_ID_MEM_KBYTE:
                        case RESOURCE_ID_SWAP_KBYTE:
                        case RESOURCE_ID_TOTAL_MEM_KBYTE:
                                printf("%s", StringBuffer_toString(Util_printRule(buf, o->action, "if %s %s", operatornames[o->operator], Str_bytesToSize(o->limit * 1024., buffer))));
                                break;

                        case RESOURCE_ID_LOAD1:
                        case RESOURCE_ID_LOAD5:
                        case RESOURCE_ID_LOAD15:
                                printf("%s", StringBuffer_toString(Util_printRule(buf, o->action, "if %s %.1f", operatornames[o->operator], o->limit / 10.0)));
                                break;

                        case RESOURCE_ID_CHILDREN:
                                printf("%s", StringBuffer_toString(Util_printRule(buf, o->action, "if %s %ld", operatornames[o->operator], o->limit)));
                                break;
                }
                printf("\n");
        }

        if (s->every.type == EVERY_SKIPCYCLES)
                printf(" %-20s = Check service every %d cycles\n", "Every", s->every.spec.cycle.number);
        else if (s->every.type == EVERY_CRON)
                printf(" %-20s = Check service every %s\n", "Every", s->every.spec.cron);
        else if (s->every.type == EVERY_NOTINCRON)
                printf(" %-20s = Don't check service every %s\n", "Every", s->every.spec.cron);

        for (ActionRate_T o = s->actionratelist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = If restarted %d times within %d cycle(s) then %s\n", "Timeout", o->count, o->cycle, StringBuffer_toString(Util_printAction(o->action->failed, buf)));
        }

        for (Mail_T o = s->maillist; o; o = o->next) {
                printf(" %-20s = %s\n", "Alert mail to", is_str_defined(o->to));
                printf("   %-18s = ", "Alert on");
                printevents(o->events);
                if (o->reminder)
                        printf("   %-18s = %u cycles\n", "Alert reminder", o->reminder);
        }

        printf("\n");

        StringBuffer_free(&buf);
}


void Util_printServiceList() {
        Service_T s;
        char ruler[STRLEN];

        printf("The service list contains the following entries:\n\n");

        for (s = servicelist_conf; s; s = s->next_conf)
                Util_printService(s);

        memset(ruler, '-', STRLEN);
        printf("%-.79s\n", ruler);
}


char *Util_monitId(char *idfile) {
        FILE *file = NULL;

        ASSERT(idfile);

        if (! file_exist(idfile)) {
                md5_context_t ctx;
                char buf[STRLEN];
                MD_T digest;
                file = fopen(idfile, "w");
                if (! file) {
                        LogError("Error opening the idfile '%s' -- %s\n", idfile, STRERROR);
                        return NULL;
                }
                /* Generate the unique id */
                snprintf(buf, STRLEN, "%lu%d%lu", (unsigned long)time(NULL), getpid(), random());
                md5_init(&ctx);
                md5_append(&ctx, (const md5_byte_t *)buf, (int)strlen(buf));
                md5_finish(&ctx, (md5_byte_t *)digest);
                Util_digest2Bytes((unsigned char *)digest, 16, Run.id);
                fprintf(file, "%s", Run.id);
                LogInfo("Generated unique Monit id %s and stored to '%s'\n", Run.id, idfile);
        } else {
                if (! file_isFile(idfile)) {
                        LogError("idfile '%s' is not a regular file\n", idfile);
                        return NULL;
                }
                if ((file = fopen(idfile,"r")) == (FILE *)NULL) {
                        LogError("Error opening the idfile '%s' -- %s\n", idfile, STRERROR);
                        return NULL;
                }
                if (fscanf(file, "%255s", Run.id) != 1) {
                        LogError("Error reading id from file '%s'\n", idfile);
                        if (fclose(file))
                                LogError("Error closing file '%s' -- %s\n", idfile, STRERROR);
                        return NULL;
                }
        }
        if (fclose(file))
                LogError("Error closing file '%s' -- %s\n", idfile, STRERROR);

        return Run.id;
}


pid_t Util_getPid(char *pidfile) {
        FILE *file = NULL;
        int pid = -1;

        ASSERT(pidfile);

        if (! file_exist(pidfile)) {
                DEBUG("pidfile '%s' does not exist\n", pidfile);
                return FALSE;
        }
        if (! file_isFile(pidfile)) {
                LogError("pidfile '%s' is not a regular file\n", pidfile);
                return FALSE;
        }
        if ((file = fopen(pidfile,"r")) == (FILE *)NULL) {
                LogError("Error opening the pidfile '%s' -- %s\n", pidfile, STRERROR);
                return FALSE;
        }
        if (fscanf(file, "%d", &pid) != 1) {
                LogError("Error reading pid from file '%s'\n", pidfile);
                if (fclose(file))
                        LogError("Error closing file '%s' -- %s\n", pidfile, STRERROR);
                return FALSE;
        }
        if (fclose(file))
                LogError("Error closing file '%s' -- %s\n", pidfile, STRERROR);

        if (pid < 0)
                return(FALSE);

        return (pid_t)pid;

}


int Util_isProcessRunning(Service_T s, int refresh) {
        pid_t pid = -1;
        ASSERT(s);
        errno = 0;
        if (s->matchlist) {
                if (refresh || ! ptree || ! ptreesize)
                        initprocesstree(&ptree, &ptreesize, &oldptree, &oldptreesize);
                /* The process table read may sporadically fail during read, because we're using glob on some platforms which may fail if the proc filesystem
                 * which it traverses is changed during glob (process stopped). Note that the glob failure is rare and temporary - it will be OK on next cycle.
                 * We skip the process matching that cycle however because we don't have process informations - will retry next cycle */
                if (Run.doprocess) {
                        for (int i = 0; i < ptreesize; i++) {
                                int found = FALSE;
                                if (ptree[i].cmdline) {
#ifdef HAVE_REGEX_H
                                        found = regexec(s->matchlist->regex_comp, ptree[i].cmdline, 0, NULL, 0) ? FALSE : TRUE;
#else
                                        found = strstr(ptree[i].cmdline, s->matchlist->match_string) ? TRUE : FALSE;
#endif
                                }
                                if (found) {
                                        pid = ptree[i].pid;
                                        break;
                                }
                        }
                } else {
                        DEBUG("Process information not available -- skipping service %s process existence check for this cycle\n", s->name);
                        /* Return value is NOOP - it is based on existing errors bitmap so we don't generate false recovery/failures */
                        return ! (s->error & Event_Nonexist);
                }
        } else {
                pid = Util_getPid(s->path);
        }
        if (pid > 0) {
                if ((getpgid(pid) > -1) || (errno == EPERM))
                        return pid;
                DEBUG("'%s' process test failed [pid=%d] -- %s\n", s->name, pid, STRERROR);
        }
        Util_resetInfo(s);
        return 0;
}


time_t Util_getProcessUptime(char *pidfile) {
        time_t ctime;

        ASSERT(pidfile);

        if ((ctime = file_getTimestamp(pidfile, S_IFREG)) ) {
                time_t now = time(&now);
                time_t since = now-ctime;
                return since;
        }
        return (time_t)-1;
}


char *Util_getUptime(time_t delta, char *sep) {
        static int min = 60;
        static int hour = 3600;
        static int day = 86400;
        long rest_d;
        long rest_h;
        long rest_m;
        char buf[STRLEN];
        char *p = buf;

        *buf = 0;
        if (delta < 0)
                return(Str_dup(""));
        if ((rest_d = delta/day)>0) {
                p += snprintf(p, STRLEN-(p-buf), "%ldd%s", rest_d,sep);
                delta -= rest_d*day;
        }
        if ((rest_h = delta/hour)>0 || (rest_d > 0)) {
                p += snprintf(p, STRLEN-(p-buf), "%ldh%s", rest_h,sep);
                delta -= rest_h*hour;
        }
        rest_m = delta/min;
        snprintf(p, STRLEN - (p - buf), "%ldm%s", rest_m, sep);

        return Str_dup(buf);
}


int Util_isurlsafe(const char *url) {
        ASSERT(url && *url);
        for (int i = 0; url[i]; i++)
                if (urlunsafe[(unsigned char)url[i]])
                        return FALSE;
        return TRUE;
}


char *Util_urlEncode(char *url) {
        char *escaped = NULL;
        if (url) {
                char *p;
                int i, n;
                for (n = i = 0; url[i]; i++)
                        if (urlunsafe[(unsigned char)(url[i])])
                                n += 2;
                p = escaped = ALLOC(i + n + 1);
                for (; *url; url++, p++) {
                        if (urlunsafe[(unsigned char)(*p = *url)]) {
                                *p++= '%';
                                *p++= b2x[(unsigned char)(*url)][0];
                                *p = b2x[(unsigned char)(*url)][1];
                        }
                }
                *p = 0;
        }
        return escaped;
}


char *Util_urlDecode(char *url) {
        if (url && *url) {
                register int x, y;
                for (x = 0, y = 0; url[y]; x++, y++) {
                        if ((url[x] = url[y]) == '+')
                                url[x] = ' ';
                        else if (url[x] == '%') {
                                if (! (url[x + 1] && url[x + 2]))
                                        break;
                                url[x] = x2c(url + y + 1);
                                y += 2;
                        }
                }
                url[x] = 0;
        }
        return url;
}


// NOTE: To be used to URL encode service names when ready
char *Util_encodeServiceName(char *name) {
        int i;
        char *s;
        ASSERT(name);
        s = Util_urlEncode(name);
        for (i = 0; s[i]; i++)
                if (s[i] == '/') return Util_replaceString(&s, "/", "%2F");
        return s;
}


char *Util_getBasicAuthHeaderMonit() {
        Auth_T c = Run.credentials;

        /* We find the first cleartext credential for authorization */
        while (c != NULL) {
                if (c->digesttype == DIGEST_CLEARTEXT && ! c->is_readonly)
                        break;
                c = c->next;
        }

        if (c)
                return Util_getBasicAuthHeader(c->uname, c->passwd);

        return NULL;
}


char *Util_getBasicAuthHeader(char *username, char *password) {
        char *auth, *b64;
        char  buf[STRLEN];

        if (!username)
                return NULL;

        snprintf(buf, STRLEN, "%s:%s", username, password ? password : "");
        if (! (b64 = encode_base64(strlen(buf), (unsigned char *)buf)) ) {
                LogError("Failed to base64 encode authentication header\n");
                return NULL;
        }
        auth = CALLOC(sizeof(char), STRLEN+1);
        snprintf(auth, STRLEN, "Authorization: Basic %s\r\n", b64);
        FREE(b64);
        return auth;
}


void Util_redirectStdFds() {
        for (int i = 0; i < 3; i++) {
                if (close(i) == -1 || open("/dev/null", O_RDWR) != i) {
                        LogError("Cannot reopen standard file descriptor (%d) -- %s\n", i, STRERROR);
                }
        }
}


void Util_closeFds() {
        int i;
#ifdef HAVE_UNISTD_H
        int max_descriptors = getdtablesize();
#else
        int max_descriptors = 1024;
#endif
        for (i = 3; i < max_descriptors; i++)
                close(i);
        errno = 0;
}


Auth_T Util_getUserCredentials(char *uname) {
        /* check allowed user names */
        for (Auth_T c = Run.credentials; c; c = c->next)
                if (c->uname && IS(c->uname, uname))
                        return c;

#ifdef HAVE_LIBPAM
        /* check allowed group names */
        return(PAMcheckUserGroup(uname));
#else
        return NULL;
#endif
}


int Util_checkCredentials(char *uname, char *outside) {
        Auth_T c = Util_getUserCredentials(uname);
        char outside_crypt[STRLEN];
        if (c == NULL)
                return FALSE;
        switch (c->digesttype) {
                case DIGEST_CLEARTEXT:
                        outside_crypt[sizeof(outside_crypt) - 1] = 0;
                        strncpy(outside_crypt, outside, sizeof(outside_crypt) - 1);
                        break;
                case DIGEST_MD5:
                {
                        char id[STRLEN];
                        char salt[STRLEN];
                        char *temp;
                        /* A password looks like this,
                         *   $id$salt$digest
                         * the '$' around the id are still part of the id.
                         */
                        id[sizeof(id) - 1] = 0;
                        strncpy(id, c->passwd, sizeof(id) - 1);
                        if (! (temp = strchr(id+1, '$'))) {
                                LogError("Password not in MD5 format.\n");
                                return FALSE;
                        }
                        temp += 1;
                        *temp = '\0';
                        salt[sizeof(salt) - 1] = 0;
                        strncpy(salt, c->passwd+strlen(id), sizeof(salt) - 1);
                        if (! (temp = strchr(salt, '$'))) {
                                LogError("Password not in MD5 format.\n");
                                return FALSE;
                        }
                        *temp = '\0';
                        if (md5_crypt(outside, id, salt, outside_crypt, sizeof(outside_crypt)) == NULL) {
                                LogError("Cannot generate MD5 digest error.\n");
                                return FALSE;
                        }
                        break;
                }
                case DIGEST_CRYPT:
                {
                        char salt[3];
                        char *temp;
                        snprintf(salt, 3, "%c%c", c->passwd[0], c->passwd[1]);
                        temp = crypt(outside, salt);
                        outside_crypt[sizeof(outside_crypt) - 1] = 0;
                        strncpy(outside_crypt, temp, sizeof(outside_crypt) - 1);
                        break;
                }
#ifdef HAVE_LIBPAM
                case DIGEST_PAM:
                        return PAMcheckPasswd(uname, outside);
                        break;
#endif
                default:
                        LogError("Unknown password digestion method.\n");
                        return FALSE;
        }

        if (strcmp(outside_crypt,c->passwd) == 0)
                return TRUE;
        return FALSE;
}


void Util_resetInfo(Service_T s) {
        s->inf->st_mode = 0;
        s->inf->st_uid = 0;
        s->inf->st_gid = 0;
        s->inf->timestamp = 0;
        switch (s->type) {
                case TYPE_FILESYSTEM:
                        s->inf->priv.filesystem.f_bsize = 0LL;
                        s->inf->priv.filesystem.f_blocks = 0LL;
                        s->inf->priv.filesystem.f_blocksfree = 0LL;
                        s->inf->priv.filesystem.f_blocksfreetotal = 0LL;
                        s->inf->priv.filesystem.f_files = 0LL;
                        s->inf->priv.filesystem.f_filesfree = 0LL;
                        s->inf->priv.filesystem.inode_percent = 0;
                        s->inf->priv.filesystem.inode_total = 0LL;
                        s->inf->priv.filesystem.space_percent = 0;
                        s->inf->priv.filesystem.space_total = 0LL;
                        s->inf->priv.filesystem._flags = -1;
                        s->inf->priv.filesystem.flags = -1;
                        break;
                case TYPE_FILE:
                        // persistent: st_ino, readpos
                        s->inf->priv.file.st_size  = 0;
                        s->inf->priv.file.st_ino_prev = 0;
                        *s->inf->priv.file.cs_sum = 0;
                        break;
                case TYPE_PROCESS:
                        s->inf->priv.process._pid = -1;
                        s->inf->priv.process._ppid = -1;
                        s->inf->priv.process.pid = -1;
                        s->inf->priv.process.ppid = -1;
                        s->inf->priv.process.uid = -1;
                        s->inf->priv.process.euid = -1;
                        s->inf->priv.process.gid = -1;
                        s->inf->priv.process.status_flag = 0;
                        s->inf->priv.process.children = 0;
                        s->inf->priv.process.mem_kbyte = 0L;
                        s->inf->priv.process.total_mem_kbyte = 0L;
                        s->inf->priv.process.mem_percent = 0;
                        s->inf->priv.process.total_mem_percent = 0;
                        s->inf->priv.process.cpu_percent = 0;
                        s->inf->priv.process.total_cpu_percent = 0;
                        s->inf->priv.process.uptime = 0;
                        break;
                default:
                        break;
        }
}


int Util_hasServiceStatus(Service_T s) {
        return((s->monitor & MONITOR_YES) && !(s->error & Event_Nonexist) && !(s->error & Event_Data));
}


char *Util_getHTTPHostHeader(Socket_T s, char *hostBuf, int len) {
        if (socket_get_remote_port(s)==80)
                snprintf(hostBuf, len, "%s", socket_get_remote_host(s));
        else
                snprintf(hostBuf, len, "%s:%d", socket_get_remote_host(s), socket_get_remote_port(s));
        return hostBuf;
}


int Util_evalQExpression(Operator_Type operator, long long left, long long right) {

        switch (operator) {
                case Operator_Greater:
                        if (left > right)
                                return TRUE;
                        break;
                case Operator_Less:
                        if (left < right)
                                return TRUE;
                        break;
                case Operator_Equal:
                        if (left == right)
                                return TRUE;
                        break;
                case Operator_NotEqual:
                case Operator_Changed:
                        if (left != right)
                                return TRUE;
                        break;
                default:
                        LogError("Unknown comparison operator\n");
                        return FALSE;
        }

        return FALSE;

}


void Util_monitorSet(Service_T s) {
        ASSERT(s);
        if (s->monitor == MONITOR_NOT) {
                s->monitor = MONITOR_INIT;
                DEBUG("'%s' monitoring enabled\n", s->name);
                State_save();
        }
}


void Util_monitorUnset(Service_T s) {
        ASSERT(s);
        if (s->monitor != MONITOR_NOT) {
                s->monitor = MONITOR_NOT;
                DEBUG("'%s' monitoring disabled\n", s->name);
        }
        s->nstart = 0;
        s->ncycle = 0;
        if (s->every.type == EVERY_SKIPCYCLES)
                s->every.spec.cycle.counter = 0;
        s->error = Event_Null;
        if (s->eventlist)
                gc_event(&s->eventlist);
        Util_resetInfo(s);
        State_save();
}


int Util_getAction(const char *action) {
        int i = 1; /* the ACTION_IGNORE has index 0 => we will start on next item */

        ASSERT(action);

        while (strlen(actionnames[i])) {
                if (IS(action, actionnames[i]))
                        return i;
                i++;
        }
        /* the action was not found */
        return ACTION_IGNORE;
}


StringBuffer_T Util_printAction(Action_T A, StringBuffer_T buf) {
        StringBuffer_append(buf, "%s", actionnames[A->id]);
        if (A->id == ACTION_EXEC) {
                command_t C = A->exec;
                for (int i = 0; C->arg[i]; i++)
                        StringBuffer_append(buf, "%s%s", i ? " " : " '", C->arg[i]);
                StringBuffer_append(buf, "'");
                if (C->has_uid)
                        StringBuffer_append(buf, " as uid %d", C->uid);
                if (C->has_gid)
                        StringBuffer_append(buf, " as gid %d", C->gid);
                StringBuffer_append(buf, " timeout %d cycle(s)", C->timeout);
        }
        return buf;
}


StringBuffer_T Util_printEventratio(Action_T action, StringBuffer_T buf) {
        if (action->cycles > 1) {
                if (action->count == action->cycles)
                        StringBuffer_append(buf, "for %d cycles ", action->cycles);
                else
                        StringBuffer_append(buf, "for %d times within %d cycles ", action->count, action->cycles);
        }
        return buf;
}


StringBuffer_T Util_printRule(StringBuffer_T buf, EventAction_T action, const char *rule, ...) {
        ASSERT(buf);
        ASSERT(action);
        ASSERT(rule);
        // Variable part
        va_list ap;
        va_start(ap, rule);
        StringBuffer_vappend(buf, rule, ap);
        va_end(ap);
        // Constant part (failure action)
        StringBuffer_append(buf, " ");
        Util_printEventratio(action->failed, buf);
        StringBuffer_append(buf, "then ");
        Util_printAction(action->failed, buf);
        // Print the success part only if it's non default action (alert is implicit => skipped for simpler output)
        if (action->succeeded->id != ACTION_IGNORE && action->succeeded->id != ACTION_ALERT) {
                StringBuffer_append(buf, " else if succeeded ");
                Util_printEventratio(action->succeeded, buf);
                StringBuffer_append(buf, "then ");
                Util_printAction(action->succeeded, buf);
        }
        return buf;
}


char *Util_portTypeDescription(Port_T p) {
        switch (p->type) {
                case SOCK_STREAM:
                        return p->SSL.use_ssl?"TCPSSL":"TCP";
                case SOCK_DGRAM:
                        return "UDP";
                default:
                        return "UNKNOWN";
        }
}


char *Util_portDescription(Port_T p, char *buf, int bufsize) {
        if (p->family == AF_INET)
                snprintf(buf, STRLEN, "INET[%s:%d%s] via %s", p->hostname, p->port, p->request ? p->request : "", Util_portTypeDescription(p));
        else if (p->family == AF_UNIX)
                snprintf(buf, STRLEN, "UNIX[%s]", p->pathname);
        else
                *buf = 0;
        return buf;
}


int Util_getfqdnhostname(char *buf, unsigned len) {
        int status;
        char hostname[STRLEN];
        struct addrinfo hints, *info = NULL;

        // Set the base hostname
        if (gethostname(hostname, sizeof(hostname))) {
                LogError("Error getting hostname -- %s\n", STRERROR);
                return -1;
        }
        snprintf(buf, len, "%s", hostname);

        // Try to look for FQDN hostname
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_CANONNAME;
        if ((status = getaddrinfo(hostname, NULL, &hints, &info))) {
                LogError("Cannot translate '%s' to FQDN name -- %s\n", hostname, status == EAI_SYSTEM ? STRERROR : gai_strerror(status));
        } else {
                for (struct addrinfo *result = info; result; result = result->ai_next) {
                        if (Str_startsWith(result->ai_canonname, hostname)) {
                                snprintf(buf, len, "%s", result->ai_canonname);
                                break;
                        }
                }
        }
        if (info)
                freeaddrinfo(info);
        return 0;
}

