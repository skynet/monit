#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>

#include "Bootstrap.h"
#include "InputStream.h"
#include "File.h"
#include "Str.h"
#include "system/System.h"

/**
 * InputStream.c unit tests. 
 */

#define DATA    "./data/stream.data"
#define TIMEOUT 50

int main(void) {
        int fd;
        InputStream_T in = NULL;

        Bootstrap(); // Need to initialize library

        printf("============> Start InputStream Tests\n\n");

        printf("=> Test0: create/destroy the file input stream\n");
        {
                in = InputStream_new(File_open(DATA, "r"));
                assert(!InputStream_isClosed(in));
                File_close(InputStream_getDescriptor(in));
                InputStream_free(&in);
                assert(in == NULL);
        }
        printf("=> Test0: OK\n\n");

        printf("=> Test1: get/set timeout\n");
        {
                assert((fd = File_open(DATA, "r")) >= 0);
                in = InputStream_new(fd);
                printf("\tCurrent timeout: %ldms\n", (long)InputStream_getTimeout(in));
                InputStream_setTimeout(in, TIMEOUT);
                assert(InputStream_getTimeout(in) == TIMEOUT);
                printf("\tTimeout set to:  %dms\n", TIMEOUT);
                File_close(fd);
                InputStream_free(&in);
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: read file by characters\n");
        {
                int byte;
                int byteno = 0;
                char content[][1] = {"l", "i", "n", "e", "1", "\n",
                                     "l", "i", "n", "e", "2", "\n",
                                     "l", "i", "n", "e", "3", "\n"};
                assert((fd = File_open(DATA, "r")) >= 0);
                in = InputStream_new(fd);
                while ((byte = InputStream_read(in)) > 0) {
                        assert(byte == *content[byteno++]);
                }
                File_close(fd);
                InputStream_free(&in);
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: read file by lines\n");
        {
                int lineno = 0;
                char line[STRLEN];
                char content[][STRLEN] = {"line1\n", "line2\n", "line3\n"};
                assert((fd = File_open(DATA, "r")) >= 0);
                in = InputStream_new(fd);
                while (InputStream_readLine(in, line, sizeof(line))) {
                        assert(Str_isEqual(content[lineno++], line));
                }
                File_close(fd);
                InputStream_free(&in);
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: read file by bytes\n");
        {
                char array[STRLEN];
                char content[] = "line1\nline2\nline3\n";
                memset(array, 0, STRLEN);
                assert((fd = File_open(DATA, "r")) >= 0);
                in = InputStream_new(fd);
                while (InputStream_readBytes(in, array, sizeof(array)-1)) {
                        assert(Str_isEqual(content, array));
                }
                File_close(fd);
                InputStream_free(&in);
        }
        printf("=> Test4: OK\n\n");

        printf("=> Test5: read a large file\n");
        {
                if ((fd = File_open("/usr/share/dict/words", "r")) >= 0) {
                        int n = 0;
                        char array[2][STRLEN + 1];
                        in = InputStream_new(fd);
                        for (int i = 0; ((n = InputStream_readBytes(in, array[i], STRLEN)) > 0); i = i ? 0 : 1)
                                assert(strncmp(array[0], array[1], STRLEN/2) != 0); // ensure that InputStream buffer is filled anew
                        File_rewind(fd);
                        // Test read data larger than InputStream's internal buffer
                        int filesize = (int)File_size("/usr/share/dict/words");
                        char *bigarray = CALLOC(1, filesize + 1);
                        n = InputStream_readBytes(in, bigarray, filesize);
                        assert(n == filesize);
                        File_close(fd);
                        InputStream_free(&in);
                        FREE(bigarray);
                } else 
                        ERROR("\t/usr/share/dict/words not available -- skipping test\n");
        }
        printf("=> Test5: OK\n\n");

        printf("=> Test6: wrong descriptor - expecting read fail\n");
        {
                in = InputStream_new(999);
                TRY
                        assert(InputStream_read(in) != -1);
                        printf("Test6: Failed");
                        exit(1); // Should not come here
                CATCH(AssertException)
                        // Passed
                END_TRY;
                InputStream_free(&in);
        }
        printf("=> Test6: OK\n\n");


        printf("============> InputStream Tests: OK\n\n");

        return 0;
}

