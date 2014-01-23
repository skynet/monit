#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <stdarg.h>

#include "Bootstrap.h"
#include "Str.h"
#include "system/System.h"
#include "Thread.h"

/**
 * System.c unity tests.
 */



int main(void) {

        Bootstrap(); // Need to initialize library

        printf("============> Start System Tests\n\n");

        printf("=> Test0: check error description\n");
        {
                const char *error;
                assert((error = System_getError(EINVAL)) != NULL);
                printf("\tEINVAL description: %s\n", error);
                errno = EINVAL;
                assert(Str_isEqual(System_getLastError(), error));

        }
        printf("=> Test0: OK\n\n");

        printf("============> System Tests: OK\n\n");

        return 0;
}
