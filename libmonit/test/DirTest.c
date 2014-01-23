#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <stdarg.h>

#include "Bootstrap.h"
#include "Str.h"
#include "system/Time.h"
#include "File.h"
#include "Dir.h"

/**
 * Dir.c unity tests. 
 */


int main(void) {
        Bootstrap(); // Need to initialize library

        printf("============> Start Dir Tests\n\n");

        printf("=> Test1: mkdir\n");
        {
                File_setUmask(022);
                assert(Dir_mkdir("X", 0));
                printf("\tResult: Dir X created with default perm = %#o\n", File_mod("X"));
                assert(File_mod("X") & 755);
                assert(Dir_mkdir("Y", 0700));
                printf("\tResult: Dir Y created with perm = %#o\n", File_mod("Y"));
                assert(File_mod("Y") & 700);
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: chdir\n");
        {
                printf("\tResult: Changing working dir to X\n");
                assert(Dir_chdir("X"));
                printf("\tResult: Changing working dir to Y\n");
                assert(Dir_chdir("../Y"));
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: getwd\n");
        {
                char cwd[STRLEN];
                assert(Dir_cwd(cwd, STRLEN));
                printf("\tResult: Current working dir is: %s\n", cwd);
                assert(Str_endsWith(cwd, "Y"));
                assert(Dir_chdir(".."));
                assert(Dir_cwd(cwd, STRLEN));
                printf("\tResult: Current working dir is: %s\n", cwd);
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: delete\n");
        {
                printf("\tResult: deleting dir X.. ");
                assert(Dir_delete("X"));
                printf("ok\n");
                printf("\tResult: deleting dir Y.. ");
                assert(Dir_delete("Y"));
                printf("ok\n");
        }
        printf("=> Test4: OK\n\n");

        printf("============> Dir Tests: OK\n\n");

        return 0;
}
