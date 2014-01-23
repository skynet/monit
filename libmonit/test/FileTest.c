#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>

#include "Bootstrap.h"
#include "Str.h"
#include "File.h"

/**
 * File.c unity tests.
 */


int main(void) {
        char path[STRLEN];

        Bootstrap(); // Need to initialize library

        printf("============> Start File Tests\n\n");

        snprintf(path, STRLEN, "/tmp/.FileTest.%d", getpid());

        printf("=> Test1: open/close\n");
        {
                int fd;
                assert((fd = File_open(path, "w")) != -1);
                assert(File_close(fd) == true);
                assert((fd = File_open(path, "w+")) != -1);
                assert(File_close(fd) == true);
                assert((fd = File_open("/a/b/c/d", "r")) == -1);
                assert((fd = File_open(path, "r")) != -1);
                assert(File_close(fd) == true);
                assert((fd = File_open(path, "r+")) != -1);
                assert(File_close(fd) == true);
                assert((fd = File_open(path, "a")) != -1);
                assert(File_close(fd) == true);
                assert((fd = File_open(path, "a+")) != -1);
                assert(write(fd, "something", sizeof("something") - 1) > 0);
                assert(File_close(fd) == true);
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: check properties (class)\n");
        {
                char c;
                int i;
                long j;
                long long k;
                struct stat s;
                assert(stat(path, &s) == 0);
                assert((j = File_mtime(path)) > 0);
                printf("\tmodification time: %ld\n", j);
                assert(j == s.st_mtime);
                assert((j = File_ctime(path)) > 0);
                printf("\tchange time: %ld\n", j);
                assert(j == s.st_ctime);
                assert((j = File_atime(path)) > 0);
                printf("\taccess time: %ld\n", j);
                assert(j == s.st_atime);
                assert((k = File_size(path)) >= 0);
                printf("\tsize: %lld B\n", k);
                assert(k == s.st_size);
                assert((c = File_isFile(path)) == true);
                assert((c = File_type(path)) == 'r');
                printf("\ttype: regular file\n");
                assert((File_exist(path)) == true);
                printf("\texist: yes\n");
                assert((i = File_mod(path)) > 0);
                printf("\tpermission mode: %o\n", i & 07777);
                assert(i == s.st_mode);
                assert(File_chmod(path, 00640) == true);
                assert((File_mod(path) & 07777) == 00640);
                assert(File_isReadable(path) == true);
                assert(File_isWritable(path) == true);
#if defined(SOLARIS) || defined (FREEBSD) || defined (AIX)
                /* Some systems like Solaris and FreeBSD return X_OK if the process has
                 * appropriate privilege even if none of the execute file permission bits
                 * are set. */
                if (getuid() == 0)
                        assert(File_isExecutable(path) == true);
                else
#endif
                assert(File_isExecutable(path) == false);
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: check directory\n");
        {
                assert(File_isDirectory("/") == true);
                assert(File_type("/") == 'd');
                assert(File_isDirectory(path) == false);
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: check umask\n");
        {
                int i;
                assert((i = File_umask()) >= 0);
                printf("\tumask: %o\n", i & 07777);
                assert(File_setUmask(0002) == i);
                assert(File_setUmask(i) == 0002);
        }
        printf("=> Test4: OK\n\n");

        printf("=> Test5: rename\n");
        {
                File_rename(path, "/tmp/.FileTest.abcde");
                snprintf(path, STRLEN, "/tmp/.FileTest.abcde"); // the file is kept for later tests
        }
        printf("=> Test5: OK\n\n");

        printf("=> Test6: path parsing\n");
        {
                char s[STRLEN];
                assert(Str_isEqual(File_basename(path), ".FileTest.abcde"));
                snprintf(s, STRLEN, "%s", path);
                assert(Str_isEqual(File_dirname(s), "/tmp/"));
                assert(Str_isEqual(File_extension(path), "abcde"));
                char dir_path[] = "/tmp/";
                assert(Str_isEqual(File_removeTrailingSeparator(dir_path), "/tmp"));
        }
        printf("=> Test6: OK\n\n");

        printf("=> Test7: normalize path\n");
        {
                char s[PATH_MAX];
                assert(File_getRealPath("/././tmp/../tmp", s) != NULL);
#ifdef DARWIN
                /* On Darwin /tmp is a link to /private/tmp */
                assert(Str_isEqual(s, "/private/tmp")); 
#else
                assert(Str_isEqual(s, "/tmp"));
#endif
        }
        printf("=> Test7: OK\n\n");

        printf("=> Test8: delete\n");
        {
                assert(File_delete(path) == true);
                assert(File_exist(path) == false);
        }
        printf("=> Test8: OK\n\n");

        printf("=> Test9: removeTrailingSeparator\n");
        {
                char a[] = "/abc/def/";
                char b[] = "/abc/def";
                assert(Str_isEqual(File_removeTrailingSeparator(a), "/abc/def"));
                assert(Str_isEqual(File_removeTrailingSeparator(b), "/abc/def"));
                assert(Str_isEqual(File_removeTrailingSeparator(""), ""));
                assert(File_removeTrailingSeparator(NULL) == NULL);
        }
        printf("=> Test9: OK\n\n");

        printf("============> File Tests: OK\n\n");

        return 0;
}


