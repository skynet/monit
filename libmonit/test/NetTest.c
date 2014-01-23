#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include "Bootstrap.h"
#include "Str.h"
#include "system/Time.h"
#include "Thread.h"
#include "system/Net.h"
#include "File.h"

/**
 * Net.c unity tests. 
 */


int main(int argc, char **argv) {

        Bootstrap(); // Need to initialize library

        printf("============> Start Net Tests\n\n");


        printf("============> Net Tests: OK\n\n");

        return 0;
}

