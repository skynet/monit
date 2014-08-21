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


#include "Config.h"

#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdlib.h>

#include "Str.h"
#include "Dir.h"
#include "File.h"
#include "List.h"
#include "system/Net.h"

#include "system/System.h"
#include "system/Time.h"
#include "system/Command.h"


/**
 * Implementation of the Command and Process interfaces.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */



/* ----------------------------------------------------------- Definitions */


#define T Command_T
struct T {
        uid_t uid;
        gid_t gid;
        List_T env;
        List_T args;
        char **_env;
        char **_args;
        char *working_directory;
};


struct Process_T {
        pid_t pid;
        uid_t uid;
        gid_t gid;
        int status;
        int stdin_pipe[2];
        int stdout_pipe[2];
        int stderr_pipe[2];
        InputStream_T in;
        InputStream_T err;
        OutputStream_T out;
        char *working_directory;
};


/* --------------------------------------------------------------- Private */


/* Search the env list and return the pointer to the name (in the list)
 if found, otherwise NULL */
static inline char *findEnv(T C, const char *name) {
        for (list_t p = C->env->head; p; p = p->next) {
                if ((strncmp(p->e, name, strlen(name)) == 0))
                        if (((char*)p->e)[strlen(name)] == '=') // Ensure that p->e is not just a sub-string
                                return p->e;
        }
        return NULL;
}


/* Remove env variable and value identified by name */
static inline void removeEnv(T C, const char *name) {
        char *e = findEnv(C, name);
        if (e) {
                List_remove(C->env, e);
                FREE(e);
        }
}


/* Free each string in a list of strings */
static void freeStrings(List_T l) {
        while (List_length(l) > 0) {
                char *s = List_pop(l);
                FREE(s);
        }
}


/* Build the Command args list. The list represent the array sent
 to execv and the List contains the following entries: args[0]
 is the path to the program, the rest are arguments to the program */
static void buildArgs(T C, const char *path, const char *x, va_list ap) {
        freeStrings(C->args);
        List_append(C->args, Str_dup(path));
        va_list ap_copy;
        va_copy(ap_copy, ap);
        for (; x; x = va_arg(ap_copy, char *))
                List_append(C->args, Str_dup(x));
        va_end(ap_copy);
}


/* Returns an array of program args */
static inline char **_args(T C) {
        if (! C->_args)
                C->_args = (char**)List_toArray(C->args);
        return C->_args;
}


/* Returns an array of program environment */
static inline char **_env(T C) {
        if (! C->_env)
                C->_env = (char**)List_toArray(C->env);
        return C->_env;
}


/* Create stdio pipes for communication between parent and child process */
static void createPipes(Process_T P) {
        if (pipe(P->stdin_pipe) < 0 || pipe(P->stdout_pipe) < 0 || pipe(P->stderr_pipe) < 0) {
                ERROR("Command pipe(2): Bad file descriptors -- %s", System_getLastError());
        }
}


/* Setup stdio pipes in subprocess */
static void setupChildPipes(Process_T P) {
        close(P->stdin_pipe[1]);   // close write end
        if (P->stdin_pipe[0] != STDIN_FILENO) {
                if (dup2(P->stdin_pipe[0],  STDIN_FILENO) != STDIN_FILENO)
                        ERROR("Command: dup2(stdin) -- %s\n", System_getLastError());
                close(P->stdin_pipe[0]);
        }
        close(P->stdout_pipe[0]);  // close read end
        if (P->stdout_pipe[1] != STDOUT_FILENO) {
                if (dup2(P->stdout_pipe[1], STDOUT_FILENO) != STDOUT_FILENO)
                        ERROR("Command: dup2(stdout) -- %s\n", System_getLastError());
                close(P->stdout_pipe[1]);
        }
        close(P->stderr_pipe[0]);  // close read end
        if (P->stderr_pipe[1] != STDERR_FILENO) {
                if (dup2(P->stderr_pipe[1], STDERR_FILENO) != STDERR_FILENO)
                        ERROR("Command: dup2(stderr) -- %s\n", System_getLastError());
                close(P->stderr_pipe[1]);
        }
}


/* Setup stdio pipes in parent process for communication with the subprocess */
static void setupParentPipes(Process_T P) {
        close(P->stdin_pipe[0]);    // close read end
        close(P->stdout_pipe[1]);   // close write end
        close(P->stderr_pipe[1]);   // close write end
        Net_setNonBlocking(P->stdin_pipe[1]);
        Net_setNonBlocking(P->stdout_pipe[0]);
        Net_setNonBlocking(P->stderr_pipe[0]);
}


/* Close stdio pipes in parent process */
static void closeParentPipes(Process_T P) {
        close(P->stdin_pipe[1]);    // close write end
        close(P->stdout_pipe[0]);   // close read end
        close(P->stderr_pipe[0]);   // close read end
}


/* Close and destroy opened stdio streams */
static void closeStreams(Process_T P) {
        if (P->in) InputStream_free(&P->in);
        if (P->err) InputStream_free(&P->err);
        if (P->out) OutputStream_free(&P->out);
}


/* -------------------------------------------------------------- Process_T */


static inline void setstatus(Process_T P) {
        if (WIFEXITED(P->status))
                P->status = WEXITSTATUS(P->status);
        else if (WIFSIGNALED(P->status))
                P->status = WTERMSIG(P->status);
        else if (WIFSTOPPED(P->status))
                P->status = WSTOPSIG(P->status);
}


static Process_T Process_new(void) {
        Process_T P;
        NEW(P);
        P->status = -1;
        return P;
}


void Process_free(Process_T *P) {
        assert(P && *P);
        FREE((*P)->working_directory);
        if (Process_isRunning(*P)) 
                Process_kill(*P);
        closeParentPipes(*P);
        closeStreams(*P);
        FREE(*P);
}


uid_t Process_getUid(Process_T P) {
        assert(P);
        return P->uid;
}


gid_t Process_getGid(Process_T P) {
        assert(P);
        return P->gid;
}


const char *Process_getDir(Process_T P) {
        assert(P);
        if (! P->working_directory) {
                char t[STRLEN];
                P->working_directory = Str_dup(Dir_cwd(t, STRLEN));
        }
        return P->working_directory;
}


pid_t Process_getPid(Process_T P) {
        assert(P);
        return P->pid;
}


int Process_waitFor(Process_T P) {
        assert(P);
        if (P->status < 0) {
                int r;
                do
                        r = waitpid(P->pid, &P->status, 0); // Wait blocking
                while (r == -1 && errno == EINTR);
                if (r != P->pid) 
                        P->status = -1;
                else 
                        setstatus(P);
        }
        return P->status;
}


int Process_exitStatus(Process_T P) {
        assert(P);
        if (P->status < 0) {
                int r;
                do
                        r = waitpid(P->pid, &P->status, WNOHANG); // Wait non-blocking
                while (r == -1 && errno == EINTR); 
                if (r == 0) // Process is still running
                        P->status = -1;
                else 
                        setstatus(P);
        }
        return P->status;
}


int Process_isRunning(Process_T P) {
        assert(P);
        errno = 0;
        return ((getpgid(P->pid) > -1) || (errno == EPERM));
}


OutputStream_T Process_getOutputStream(Process_T P) {
        assert(P);
        if (! P->out)
                P->out = OutputStream_new(P->stdin_pipe[1]);
        return P->out;
}


InputStream_T Process_getInputStream(Process_T P) {
        assert(P);
        if (! P->in)
                P->in = InputStream_new(P->stdout_pipe[0]);
        return P->in;
}


InputStream_T Process_getErrorStream(Process_T P) {
        assert(P);
        if (! P->err)
                P->err = InputStream_new(P->stderr_pipe[0]);
        return P->err;
}


void Process_terminate(Process_T P) {
        assert(P);
        kill(P->pid, SIGTERM);
}


void Process_kill(Process_T P) {
        assert(P);
        kill(P->pid, SIGKILL);
}


/* ---------------------------------------------------------------- Public */


T Command_new(const char *path, const char *arg0, ...) {
        T C;
        assert(path);
        if (! File_exist(path))
                THROW(AssertException, "File '%s' does not exist", path);
        NEW(C);
        C->env = List_new();
        C->args = List_new();
        va_list ap;
        va_start(ap, arg0);
        buildArgs(C, path, arg0, ap);
        va_end(ap);
        // Copy this process's environment for transit to sub-processes
        extern char **environ;
        for (char **e = environ; *e; e++) {
                List_append(C->env, Str_dup(*e));
        }
        return C;
}


void Command_free(T *C) {
        assert(C && *C);
        FREE((*C)->_args);
        FREE((*C)->_env);
        freeStrings((*C)->args);
        List_free(&(*C)->args);
        freeStrings((*C)->env);
        List_free(&(*C)->env);
        FREE((*C)->working_directory);
        FREE(*C);
}


void Command_appendArgument(T C, const char *argument) {
        assert(C);
        if (argument)
                List_append(C->args, Str_dup(argument));
        FREE(C->_args); // Recreate Command argument on exec
}


void Command_setUid(T C, uid_t uid) {
        assert(C);
        C->uid = uid;
}


uid_t Command_getUid(T C) {
        assert(C);
        return C->uid;
}


void Command_setGid(T C, gid_t gid) {
        assert(C);
        C->gid = gid;
}


gid_t Command_getGid(T C) {
        assert(C);
        return C->gid;
}


void Command_setDir(T C, const char *dir) {
        assert(C);
        if (dir) { // Allow to set a NULL directory, meaning the calling process's current directory
                if (! File_isDirectory(dir))
                        THROW(AssertException, "The new working directory '%s' is not a directory", dir);
                if (! File_isExecutable(dir))
                        THROW(AssertException, "The new working directory '%s' is not accessible", dir);
        }
        FREE(C->working_directory);
        C->working_directory = Str_dup(dir);
        File_removeTrailingSeparator(C->working_directory);
}


const char *Command_getDir(Command_T C) {
        assert(C);
        return C->working_directory;
}


/* Env variables are stored in the environment list as "name=value" strings */
void Command_setEnv(Command_T C, const char *name, const char *value) {
        assert(C);
        assert(name);
        removeEnv(C, name);
        List_append(C->env, Str_cat("%s=%s", name, value ? value : ""));
        FREE(C->_env); // Recreate Command environment on exec
}


void Command_setEnvLong(Command_T C, const char *name, long value) {
        assert(C);
        assert(name);
        removeEnv(C, name);
        List_append(C->env, Str_cat("%s=%ld", name, value));
        FREE(C->_env); // Recreate Command environment on exec
}


/* Returns the value part from a "name=value" environment string */
const char *Command_getEnv(Command_T C, const char *name) {
        assert(C);
        assert(name);
        char *e = findEnv(C, name);
        if (e) {
                char *v = strchr(e, '=');
                if (v)
                        return ++v;   
        }
        return NULL;
}


List_T Command_getCommand(T C) {
        assert(C);
        return C->args;
}


/* The Execute function. Note that we use vfork() rather than fork. Vfork has
 a special semantic in that the child process runs in the parent address space
 until exec is called in the child. The child also run first and suspend the
 parent process until exec or exit is called */
Process_T Command_execute(T C) {
        assert(C);
        assert(_env(C));
        assert(_args(C));
        volatile int exec_error = 0;
        Process_T P = Process_new();
        createPipes(P);
        if ((P->pid = vfork()) < 0) {
                ERROR("Command: fork failed -- %s\n", System_getLastError());
                Process_free(&P);
                return NULL;
        } else if (P->pid == 0) { 
                // Child
                if (C->working_directory) {
                        if (! Dir_chdir(C->working_directory)) {
                                exec_error = errno;
                                ERROR("Command: sub-process cannot change working directory to '%s' -- %s\n", C->working_directory, System_getLastError());
                                _exit(errno);
                        }
                }
                if (C->uid)
                        P->uid = (setuid(C->uid) != 0) ? ERROR("Command: Cannot change process uid to '%d' -- %s\n", C->uid, System_getLastError()), getuid() : C->uid;
                else
                        P->uid = getuid();
                if (C->gid)
                        P->gid = (setgid(C->gid) != 0) ? ERROR("Command: Cannot change process gid to '%d' -- %s\n", C->gid, System_getLastError()), getgid() : C->gid;
                else
                        P->gid = getgid();
                setsid(); // Loose controlling terminal
                setupChildPipes(P);
                // Close all descriptors except stdio
                for (int i = 3, descriptors = getdtablesize(); i < descriptors; i++)
                        close(i);
                // Unblock any signals and reset signal handlers
                sigset_t mask;
                sigemptyset(&mask);
                pthread_sigmask(SIG_SETMASK, &mask, NULL);
                signal(SIGINT, SIG_DFL);
                signal(SIGQUIT, SIG_DFL);
                signal(SIGABRT, SIG_DFL);
                signal(SIGTERM, SIG_DFL);
                signal(SIGPIPE, SIG_DFL);
                signal(SIGCHLD, SIG_DFL); 
                signal(SIGUSR1, SIG_DFL);
                signal(SIGHUP, SIG_IGN);  // Ensure future opens won't allocate controlling TTYs
                // Execute the program
                execve(_args(C)[0], _args(C), _env(C));
                exec_error = errno;
                _exit(errno);
        }
        // Parent
        if (exec_error != 0)
                Process_free(&P);
        else
                setupParentPipes(P);
        errno = exec_error;
        return P;
}

