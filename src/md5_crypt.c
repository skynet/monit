/*
 * From crypt implementation 1.7 by Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * Sub-licensed with modifications under AGPL:
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "md5.h"


/* 0 ... 63 => ascii - 64 */
static unsigned char itoa64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void to64(char *s, unsigned long v, int n) {
        while (--n >= 0) {
                *s++ = itoa64[v & 0x3f];
                v >>= 6;
        }
}


/*
 * UNIX password MD5
 */
char *md5_crypt(const char *pw, const char *id, const char *salt, char *buf, int buflen) {
        char *p;
        const md5_byte_t *sp, *ep;
        unsigned char final[16];
        int sl, pl, pwl = (int)strlen(pw);
        unsigned long l;
        md5_context_t ctx, ctx1;

        /* Refine the Salt first */
        sp = (const md5_byte_t *)salt;

        /* If it starts with the id string, then skip that */
        if (! strncmp(salt, id, strlen(id)))
                sp += strlen(id);

        /* It stops at the first '$', max 8 chars */
        for (ep = sp; *ep && *ep != '$' && ep < (sp + 8); ep++)
                continue;

        /* get the length of the true salt */
        sl = (int)(ep - sp);

        md5_init(&ctx);

        /* The password first, since that is what is most unknown */
        md5_append(&ctx, (const md5_byte_t *)pw, pwl);

        /* Then our id string */
        md5_append(&ctx, (const md5_byte_t *)id, (int)strlen(id));

        /* Then the raw salt */
        md5_append(&ctx, sp, sl);

        /* Then just as many characters of the MD5(pw, salt, pw) */
        md5_init(&ctx1);
        md5_append(&ctx1, (const md5_byte_t *)pw, pwl);
        md5_append(&ctx1, sp, sl);
        md5_append(&ctx1, (const md5_byte_t *)pw, pwl);
        md5_finish(&ctx1, final);
        for (pl = pwl; pl > 0; pl -= 16)
                md5_append(&ctx, final, pl > 16 ? 16 : pl);

        /* Don't leave anything around in vm they could use. */
        memset(final, 0, sizeof(final));

        /* Then something really weird... */
        for (int i = pwl; i; i >>= 1) {
                if (i & 1)
                        md5_append(&ctx, final, 1);
                else
                        md5_append(&ctx, (const md5_byte_t *)pw, 1);
        }

        /* Now make the output string */
        strncpy(buf, id, buflen);
        strncat(buf, (const char *)sp, sl);
        strcat(buf, "$");

        md5_finish(&ctx, final);

        /*
         * and now, just to make sure things don't run too fast
         * On a 60 Mhz Pentium this takes 34 msec, so you would
         * need 30 seconds to build a 1000 entry dictionary...
         */
        for (int i = 0; i < 1000; i++) {
                md5_init(&ctx1);
                if (i & 1)
                        md5_append(&ctx1, (const md5_byte_t *)pw, pwl);
                else
                        md5_append(&ctx1, final, 16);

                if (i % 3)
                        md5_append(&ctx1, sp, sl);

                if (i % 7)
                        md5_append(&ctx1, (const md5_byte_t *)pw, pwl);

                if (i & 1)
                        md5_append(&ctx1, final, 16);
                else
                        md5_append(&ctx1, (const md5_byte_t *)pw, pwl);
                md5_finish(&ctx1, final);
        }

        p = buf + strlen(buf);

        l = (final[ 0] << 16) | (final[ 6] << 8) | final[12]; to64(p, l, 4); p += 4;
        l = (final[ 1] << 16) | (final[ 7] << 8) | final[13]; to64(p, l, 4); p += 4;
        l = (final[ 2] << 16) | (final[ 8] << 8) | final[14]; to64(p, l, 4); p += 4;
        l = (final[ 3] << 16) | (final[ 9] << 8) | final[15]; to64(p, l, 4); p += 4;
        l = (final[ 4] << 16) | (final[10] << 8) | final[ 5]; to64(p, l, 4); p += 4;
        l =                        final[11]                ; to64(p, l, 2); p += 2;
        *p = '\0';

        /* Don't leave anything around in vm they could use. */
        memset(final, 0, sizeof(final));

        return buf;
}

