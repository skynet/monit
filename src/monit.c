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
#include <locale.h>

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "monit.h"
#include "net.h"
#include "ssl.h"
#include "process.h"
#include "state.h"
#include "event.h"

// libmonit
#include "Bootstrap.h"
#include "io/Dir.h"
#include "io/File.h"
#include "exceptions/AssertException.h"


/**
 *  DESCRIPTION
 *    monit - system for monitoring services on a Unix system
 *
 *  SYNOPSIS
 *    monit [options] {arguments}
 *
 *  @file
 */


/* -------------------------------------------------------------- Prototypes */


static void  do_init();                       /* Initialize this application */
static void  do_reinit();           /* Re-initialize the runtime application */
static void  do_action(char **);         /* Dispatch to the submitted action */
static void  do_exit();                                    /* Finalize monit */
static void  do_default();                              /* Do default action */
static void  handle_options(int, char **);         /* Handle program options */
static void  help();                 /* Print program help message to stdout */
static void  version();                         /* Print version information */
static void *heartbeat(void *args);              /* M/Monit heartbeat thread */
static RETSIGTYPE do_reload(int);       /* Signalhandler for a daemon reload */
static RETSIGTYPE do_destroy(int);   /* Signalhandler for monit finalization */
static RETSIGTYPE do_wakeup(int);  /* Signalhandler for a daemon wakeup call */
static void waitforchildren(void); /* Wait for any child process not running */



/* ------------------------------------------------------------------ Global */


const char *prog;                              /**< The Name of this Program */
struct myrun Run;                      /**< Struct holding runtime constants */
Service_T servicelist;                /**< The service list (created in p.y) */
Service_T servicelist_conf;   /**< The service list in conf file (c. in p.y) */
ServiceGroup_T servicegrouplist;/**< The service group list (created in p.y) */
SystemInfo_T systeminfo;                              /**< System infomation */

pthread_t           heartbeatThread;           /**< M/Monit heartbeat thread */
pthread_cond_t      heartbeatCond;            /**< Hearbeat wakeup condition */
pthread_mutex_t     heartbeatMutex;                      /**< Hearbeat mutex */
static volatile int heartbeatRunning = FALSE;     /**< Heartbeat thread flag */

int ptreesize = 0;
int oldptreesize = 0;
ProcessTree_T *ptree = NULL;
ProcessTree_T *oldptree = NULL;

char *actionnames[] = {"ignore", "alert", "restart", "stop", "exec", "unmonitor", "start", "monitor", ""};
char *modenames[] = {"active", "passive", "manual"};
char *checksumnames[] = {"UNKNOWN", "MD5", "SHA1"};
char *operatornames[] = {"greater than", "less than", "equal to", "not equal to"};
char *operatorshortnames[] = {">", "<", "=", "!="};
char *statusnames[] = {"Accessible", "Accessible", "Accessible", "Running", "Online with all services", "Running", "Accessible", "Status ok"};
char *servicetypes[] = {"Filesystem", "Directory", "File", "Process", "Remote Host", "System", "Fifo", "Program"};
char *pathnames[] = {"Path", "Path", "Path", "Pid file", "Path", "", "Path"};
char *icmpnames[] = {"Echo Reply", "", "", "Destination Unreachable", "Source Quench", "Redirect", "", "", "Echo Request", "", "", "Time Exceeded", "Parameter Problem", "Timestamp Request", "Timestamp Reply", "Information Request", "Information Reply", "Address Mask Request", "Address Mask Reply"};
char *sslnames[] = {"auto", "v2", "v3", "tls"};




/* ------------------------------------------------------------------ Public */


/**
 * The Prime mover
 */
int main(int argc, char **argv) {
        Bootstrap(); // Bootstrap libmonit
        Bootstrap_setAbortHandler(vLogAbortHandler);  // Abort Monit on exceptions thrown by libmonit
        Bootstrap_setErrorHandler(vLogError);
        setlocale(LC_ALL, "C");
        prog = File_basename(argv[0]);
        init_env();
        handle_options(argc, argv);
        do_init();
        do_action(argv);
        do_exit();
        return 0;
}


/**
 * Wakeup a sleeping monit daemon.
 * Returns TRUE on success otherwise FALSE
 */
int do_wakeupcall() {
        pid_t pid;

        if ((pid = exist_daemon()) > 0) {
                kill(pid, SIGUSR1);
                LogInfo("%s daemon with PID %d awakened\n", prog, pid);

                return TRUE;
        }

        return FALSE;
}


/* ----------------------------------------------------------------- Private */


/**
 * Initialize this application - Register signal handlers,
 * Parse the control file and initialize the program's
 * datastructures and the log system.
 */
static void do_init() {

        int status;

        /*
         * Register interest for the SIGTERM signal,
         * in case we run in daemon mode this signal
         * will terminate a running daemon.
         */
        signal(SIGTERM, do_destroy);

        /*
         * Register interest for the SIGUSER1 signal,
         * in case we run in daemon mode this signal
         * will wakeup a sleeping daemon.
         */
        signal(SIGUSR1, do_wakeup);

        /*
         * Register interest for the SIGINT signal,
         * in case we run as a server but not as a daemon
         * we need to catch this signal if the user pressed
         * CTRL^C in the terminal
         */
        signal(SIGINT, do_destroy);

        /*
         * Register interest for the SIGHUP signal,
         * in case we run in daemon mode this signal
         * will reload the configuration.
         */
        signal(SIGHUP, do_reload);

        /*
         * Register no interest for the SIGPIPE signal,
         */
        signal(SIGPIPE, SIG_IGN);

        /*
         * Initialize the random number generator
         */
        srandom((unsigned)(time(NULL) + getpid()));

        /*
         * Initialize the Runtime mutex. This mutex
         * is used to synchronize handling of global
         * service data
         */
        status = pthread_mutex_init(&Run.mutex, NULL);
        if (status != 0) {
                LogError("Cannot initialize mutex -- %s\n", strerror(status));
                exit(1);
        }

        /*
         * Initialize heartbeat mutex and condition
         */
        status = pthread_mutex_init(&heartbeatMutex, NULL);
        if (status != 0) {
                LogError("Cannot initialize heartbeat mutex -- %s\n", strerror(status));
                exit(1);
        }
        status = pthread_cond_init(&heartbeatCond, NULL);
        if (status != 0) {
                LogError("Cannot initialize heartbeat condition -- %s\n", strerror(status));
                exit(1);
        }

        /*
         * Get the position of the control file
         */
        if (! Run.controlfile)
                Run.controlfile = file_findControlFile();

        /*
         * Initialize the process information gathering interface
         */
        Run.doprocess = init_process_info();

        /*
         * Start the Parser and create the service list. This will also set
         * any Runtime constants defined in the controlfile.
         */
        if (! parse(Run.controlfile))
                exit(1);

        /*
         * Initialize the log system
         */
        if (! log_init())
                exit(1);

        /*
         * Did we find any service ?
         */
        if (! servicelist) {
                LogError("No services has been specified\n");
                exit(0);
        }

        /*
         * Initialize Runtime file variables
         */
        file_init();

        /*
         * Should we print debug information ?
         */
        if (Run.debug) {
                Util_printRunList();
                Util_printServiceList();
        }

        /*
         * Reap any stray child processes we may have created
         */
        atexit(waitforchildren);
}


/**
 * Re-Initialize the application - called if a
 * monit daemon receives the SIGHUP signal.
 */
static void do_reinit() {
        int status;

        LogInfo("Awakened by the SIGHUP signal\n");
        LogInfo("Reinitializing %s - Control file '%s'\n", prog, Run.controlfile);

        /* Wait non-blocking for any children that has exited. Since we
         reinitialize any information about children we have setup to wait
         for will be lost. This may create zombie processes until Monit
         itself exit. However, Monit will wait on all children that has exited
         before it ifself exit. TODO: Later refactored versions will use a
         globale process table which a sigchld handler can check */
        waitforchildren();

        if(Run.mmonits && heartbeatRunning) {
                if ((status = pthread_cond_signal(&heartbeatCond)) != 0)
                        LogError("Failed to signal the heartbeat thread -- %s\n", strerror(status));
                if ((status = pthread_join(heartbeatThread, NULL)) != 0)
                        LogError("Failed to stop the heartbeat thread -- %s\n", strerror(status));
                heartbeatRunning = FALSE;
        }

        Run.doreload = FALSE;

        /* Stop http interface */
        if (Run.dohttpd)
                monit_http(STOP_HTTP);

        /* Save the current state (no changes are possible now since the http thread is stopped) */
        State_save();
        State_close();

        /* Run the garbage collector */
        gc();

        if (! parse(Run.controlfile)) {
                LogError("%s daemon died\n", prog);
                exit(1);
        }

        /* Close the current log */
        log_close();

        /* Reinstall the log system */
        if (! log_init())
                exit(1);

        /* Did we find any services ?  */
        if (! servicelist) {
                LogError("No services has been specified\n");
                exit(0);
        }

        /* Reinitialize Runtime file variables */
        file_init();

        if (! file_createPidFile(Run.pidfile)) {
                LogError("%s daemon died\n", prog);
                exit(1);
        }

        /* Update service data from the state repository */
        if (! State_open())
                exit(1);
        State_update();

        /* Start http interface */
        if (can_http())
                monit_http(START_HTTP);

        /* send the monit startup notification */
        Event_post(Run.system, Event_Instance, STATE_CHANGED, Run.system->action_MONIT_RELOAD, "Monit reloaded");

        if(Run.mmonits && ((status = pthread_create(&heartbeatThread, NULL, heartbeat, NULL)) != 0))
                LogError("Failed to create the heartbeat thread -- %s\n", strerror(status));
        else
                heartbeatRunning = TRUE;
}


/**
 * Dispatch to the submitted action - actions are program arguments
 */
static void do_action(char **args) {
        char *action = args[optind];
        char *service = args[++optind];

        Run.once = TRUE;

        if (! action) {
                do_default();
        } else if (IS(action, "start")     ||
                   IS(action, "stop")      ||
                   IS(action, "monitor")   ||
                   IS(action, "unmonitor") ||
                   IS(action, "restart")) {
                if (Run.mygroup || service) {
                        int errors = 0;
                        int (*_control_service)(const char *, const char *) = exist_daemon() ? control_service_daemon : control_service_string;

                        if (Run.mygroup) {
                                ServiceGroup_T sg = NULL;

                                for (sg = servicegrouplist; sg; sg = sg->next) {
                                        if (! strcasecmp(Run.mygroup, sg->name)) {
                                                ServiceGroupMember_T sgm = NULL;

                                                for (sgm = sg->members; sgm; sgm = sgm->next)
                                                        if (! _control_service(sgm->name, action))
                                                                errors++;

                                                break;
                                        }
                                }
                        } else if (IS(service, "all")) {
                                Service_T s = NULL;

                                for (s = servicelist; s; s = s->next) {
                                        if (s->visited)
                                                continue;
                                        if (! _control_service(s->name, action))
                                                errors++;
                                }
                        } else {
                                errors = _control_service(service, action) ? 0 : 1;
                        }
                        if (errors)
                                exit(1);
                } else {
                        LogError("Please specify a service name or 'all' after %s\n", action);
                        exit(1);
                }
        } else if (IS(action, "reload")) {
                LogInfo("Reinitializing %s daemon\n", prog);
                kill_daemon(SIGHUP);
        } else if (IS(action, "status")) {
                status(LEVEL_NAME_FULL);
        } else if (IS(action, "summary")) {
                status(LEVEL_NAME_SUMMARY);
        } else if (IS(action, "procmatch")) {
                if (! service) {
                        printf("Invalid syntax - usage: procmatch \"<pattern>\"\n");
                        exit(1);
                }
                process_testmatch(service);
        } else if (IS(action, "quit")) {
                kill_daemon(SIGTERM);
        } else if (IS(action, "validate")) {
                if (! validate())
                        exit(1);
        } else {
                LogError("Invalid argument -- %s  (-h will show valid arguments)\n", action);
                exit(1);
        }
}


/**
 * Finalize monit
 */
static void do_exit() {
        int status;
        sigset_t ns;

        set_signal_block(&ns, NULL);
        Run.stopped = TRUE;
        if (Run.isdaemon && !Run.once) {
                if (can_http())
                        monit_http(STOP_HTTP);

                if(Run.mmonits && heartbeatRunning) {
                        if ((status = pthread_cond_signal(&heartbeatCond)) != 0)
                                LogError("Failed to signal the heartbeat thread -- %s\n", strerror(status));
                        if ((status = pthread_join(heartbeatThread, NULL)) != 0)
                                LogError("Failed to stop the heartbeat thread -- %s\n", strerror(status));
                        heartbeatRunning = FALSE;
                }

                LogInfo("%s daemon with pid [%d] killed\n", prog, (int)getpid());

                /* send the monit stop notification */
                Event_post(Run.system, Event_Instance, STATE_CHANGED, Run.system->action_MONIT_STOP, "Monit stopped");
        }
        gc();
        exit(0);
}


/**
 * Default action - become a daemon if defined in the Run object and
 * run validate() between sleeps. If not, just run validate() once.
 * Also, if specified, start the monit http server if in deamon mode.
 */
static void do_default() {
        int status;

        if (Run.isdaemon) {
                if (do_wakeupcall())
                        exit(0);

                Run.once = FALSE;
                if (can_http())
                        LogInfo("Starting %s daemon with http interface at [%s:%d]\n", prog, Run.bind_addr?Run.bind_addr:"*", Run.httpdport);
                else
                        LogInfo("Starting %s daemon\n", prog);

                if (Run.startdelay)
                        LogInfo("Monit start delay set -- pause for %ds\n", Run.startdelay);

                if (Run.init != TRUE)
                        daemonize();
                else if (! Run.debug)
                        Util_redirectStdFds();

                if (! file_createPidFile(Run.pidfile)) {
                        LogError("%s daemon died\n", prog);
                        exit(1);
                }

                if (! State_open())
                        exit(1);
                State_update();

                atexit(file_finalize);

                if (Run.startdelay) {
                        time_t now = time(NULL);
                        time_t delay = now + Run.startdelay;

                        /* sleep can be interrupted by signal => make sure we paused long enough */
                        while (now < delay) {
                                sleep((unsigned int)(delay - now));
                                if (Run.stopped)
                                        do_exit();
                                now = time(NULL);
                        }
                }

                if (can_http())
                        monit_http(START_HTTP);

                /* send the monit startup notification */
                Event_post(Run.system, Event_Instance, STATE_CHANGED, Run.system->action_MONIT_START, "Monit started");

                if(Run.mmonits && ((status = pthread_create(&heartbeatThread, NULL, heartbeat, NULL)) != 0))
                        LogError("Failed to create the heartbeat thread -- %s\n", strerror(status));
                else
                        heartbeatRunning = TRUE;

                while (TRUE) {
                        validate();
                        State_save();

                        /* In the case that there is no pending action then sleep */
                        if (!Run.doaction)
                                sleep(Run.polltime);

                        if (Run.dowakeup) {
                                Run.dowakeup = FALSE;
                                LogInfo("Awakened by User defined signal 1\n");
                        }

                        if (Run.stopped)
                                do_exit();
                        else if (Run.doreload)
                                do_reinit();
                }
        } else {
                validate();
        }
}


/**
 * Handle program options - Options set from the commandline
 * takes precedence over those found in the control file
 */
static void handle_options(int argc, char **argv) {
        int opt;
        int deferred_opt = 0;
        opterr = 0;
        Run.mygroup = NULL;
        const char *shortopts = "c:d:g:l:p:s:HIirtvVh";
#ifdef HAVE_GETOPT_LONG
        struct option longopts[] = {
                {"conf",        required_argument,      NULL,   'c'},
                {"daemon",      required_argument,      NULL,   'd'},
                {"group",       required_argument,      NULL,   'g'},
                {"logfile",     required_argument,      NULL,   'l'},
                {"pidfile",     required_argument,      NULL,   'p'},
                {"statefile",   required_argument,      NULL,   's'},
                {"hash",        optional_argument,      NULL,   'H'},
                {"interactive", no_argument,            NULL,   'I'},
                {"id",          no_argument,            NULL,   'i'},
                {"resetid",     no_argument,            NULL,   'r'},
                {"test",        no_argument,            NULL,   't'},
                {"verbose",     no_argument,            NULL,   'v'},
                {"version",     no_argument,            NULL,   'V'},
                {"help",        no_argument,            NULL,   'h'},
                {0}
        };
        while ((opt = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1)
#else
        while ((opt = getopt(argc, argv, shortopts)) != -1)
#endif
        {
                switch (opt) {
                        case 'c':
                        {
                                char *f = optarg;
                                if (f[0] != SEPARATOR_CHAR)
                                        f = File_getRealPath(optarg, (char[PATH_MAX]){});
                                if (! f)
                                        THROW(AssertException, "The control file '%s' does not exist at %s",
                                              Str_trunc(optarg, 80), Dir_cwd((char[STRLEN]){}, STRLEN));
                                if (! File_isFile(f))
                                        THROW(AssertException, "The control file '%s' is not a file", Str_trunc(f, 80));
                                if (! File_isReadable(f))
                                        THROW(AssertException, "The control file '%s' is not readable", Str_trunc(f, 80));
                                Run.controlfile = Str_dup(f);
                                break;
                        }
                        case 'd':
                        {
                                Run.isdaemon = TRUE;
                                sscanf(optarg, "%d", &Run.polltime);
                                if (Run.polltime < 1) {
                                        LogError("Option -%c requires a natural number\n", opt);
                                        exit(1);
                                }
                                break;
                        }
                        case 'g':
                        {
                                Run.mygroup = Str_dup(optarg);
                                break;
                        }
                        case 'l':
                        {
                                Run.logfile = Str_dup(optarg);
                                if (IS(Run.logfile, "syslog"))
                                        Run.use_syslog = TRUE;
                                Run.dolog = TRUE;
                                break;
                        }
                        case 'p':
                        {
                                Run.pidfile = Str_dup(optarg);
                                break;
                        }
                        case 's':
                        {
                                Run.statefile = Str_dup(optarg);
                                break;
                        }
                        case 'I':
                        {
                                Run.init = TRUE;
                                break;
                        }
                        case 'i':
                        {
                                deferred_opt = 'i';
                                break;
                        }
                        case 'r':
                        {
                                deferred_opt = 'r';
                                break;
                        }
                        case 't':
                        {
                                deferred_opt = 't';
                                break;
                        }
                        case 'v':
                        {
                                Run.debug++;
                                break;
                        }
                        case 'H':
                        {
                                if (argc > optind)
                                        Util_printHash(argv[optind]);
                                else
                                        Util_printHash(NULL);
                                exit(0);
                                break;
                        }
                        case 'V':
                        {
                                version();
                                exit(0);
                                break;
                        }
                        case 'h':
                        {
                                help();
                                exit(0);
                                break;
                        }
                        case '?':
                        {
                                switch(optopt) {
                                        case 'c':
                                        case 'd':
                                        case 'g':
                                        case 'l':
                                        case 'p':
                                        case 's':
                                        {
                                                LogError("Option -- %c requires an argument\n", optopt);
                                                break;
                                        }
                                        default:
                                        {
                                                LogError("Invalid option -- %c  (-h will show valid options)\n", optopt);
                                        }
                                }
                                exit(1);
                        }
                }
        }
        /* Handle deferred options to make arguments to the program positional
         independent. These options are handled last, here as they represent exit
         points in the application and the control-file might be set with -c and
         these options need to respect the new control-file location as they call
         do_init */
        switch (deferred_opt) {
                case 't':
                {
                        do_init(); // Parses control file and initialize program, exit on error
                        printf("Control file syntax OK\n");
                        exit(0);
                        break;
                }
                case 'r':
                {
                        do_init();
                        assert(Run.id);
                        printf("Reset Monit Id? [Y/N]> ");
                        if (getchar() == 'Y') {
                                File_delete(Run.idfile);
                                Util_monitId(Run.idfile);
                        }
                        exit(0);
                        break;
                }
                case 'i':
                {
                        do_init();
                        assert(Run.id);
                        printf("Monit ID: %s\n", Run.id);
                        exit(0);
                        break;
                }
        }
}


/**
 * Print the program's help message
 */
static void help() {
        printf("Usage: %s [options] {arguments}\n", prog);
        printf("Options are as follows:\n");
        printf(" -c file       Use this control file\n");
        printf(" -d n          Run as a daemon once per n seconds\n");
        printf(" -g name       Set group name for start, stop, restart, monitor and unmonitor\n");
        printf(" -l logfile    Print log information to this file\n");
        printf(" -p pidfile    Use this lock file in daemon mode\n");
        printf(" -s statefile  Set the file monit should write state information to\n");
        printf(" -I            Do not run in background (needed for run from init)\n");
        printf(" --id          Print Monit's unique ID\n");
        printf(" --resetid     Reset Monit's unique ID. Use with caution\n");
        printf(" -t            Run syntax check for the control file\n");
        printf(" -v            Verbose mode, work noisy (diagnostic output)\n");
        printf(" -vv           Very verbose mode, same as -v plus log stacktrace on error\n");
        printf(" -H [filename] Print SHA1 and MD5 hashes of the file or of stdin if the\n");
        printf("               filename is omited; monit will exit afterwards\n");
        printf(" -V            Print version number and patchlevel\n");
        printf(" -h            Print this text\n");
        printf("Optional action arguments for non-daemon mode are as follows:\n");
        printf(" start all           - Start all services\n");
        printf(" start name          - Only start the named service\n");
        printf(" stop all            - Stop all services\n");
        printf(" stop name           - Only stop the named service\n");
        printf(" restart all         - Stop and start all services\n");
        printf(" restart name        - Only restart the named service\n");
        printf(" monitor all         - Enable monitoring of all services\n");
        printf(" monitor name        - Only enable monitoring of the named service\n");
        printf(" unmonitor all       - Disable monitoring of all services\n");
        printf(" unmonitor name      - Only disable monitoring of the named service\n");
        printf(" reload              - Reinitialize monit\n");
        printf(" status              - Print full status information for each service\n");
        printf(" summary             - Print short status information for each service\n");
        printf(" quit                - Kill monit daemon process\n");
        printf(" validate            - Check all services and start if not running\n");
        printf(" procmatch <pattern> - Test process matching pattern\n");
        printf("\n");
        printf("(Action arguments operate on services defined in the control file)\n");
}

/**
 * Print version information
 */
static void version() {
        printf("This is Monit version " VERSION "\n");
        printf("Copyright (C) 2001-2014 Tildeslash Ltd.");
        printf(" All Rights Reserved.\n");
}


/**
 * M/Monit heartbeat thread
 */
static void *heartbeat(void *args) {
        sigset_t ns;
        struct timespec wait;

        set_signal_block(&ns, NULL);
        LogInfo("M/Monit heartbeat started\n");
        LOCK(heartbeatMutex)
        {
                while (! Run.stopped && ! Run.doreload) {
                        handle_mmonit(NULL);
                        wait.tv_sec = time(NULL) + Run.polltime;
                        wait.tv_nsec = 0;
                        pthread_cond_timedwait(&heartbeatCond, &heartbeatMutex, &wait);
                }
        }
        END_LOCK;
        LogInfo("M/Monit heartbeat stopped\n");
        return NULL;
}


/**
 * Signalhandler for a daemon reload call
 */
static RETSIGTYPE do_reload(int sig) {
        Run.doreload = TRUE;
}


/**
 * Signalhandler for monit finalization
 */
static RETSIGTYPE do_destroy(int sig) {
        Run.stopped = TRUE;
}


/**
 * Signalhandler for a daemon wakeup call
 */
static RETSIGTYPE do_wakeup(int sig) {
        Run.dowakeup = TRUE;
}


/* A simple non-blocking reaper to ensure that we wait-for and reap all/any stray child processes
 we may have created and not waited on, so we do not create any zombie processes at exit */
static void waitforchildren(void) {
        while (waitpid(-1, NULL, WNOHANG) > 0) ;
}
