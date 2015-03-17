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


#ifndef MONIT_H
#define MONIT_H

#include "config.h"
#include <assert.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_MACH_BOOLEAN_H
#include <mach/boolean.h>
#endif
#ifdef HAVE_UVM_UVM_PARAM_H
#include <uvm/uvm_param.h>
#endif
#ifdef HAVE_VM_VM_H
#include <vm/vm.h>
#endif


//FIXME: we can export this type in libmonit
#ifndef HAVE_BOOLEAN_T
#undef true
#undef false
typedef enum {
        false = 0,
        true
} __attribute__((__packed__)) boolean_t;
#else
#define false 0
#define true  1
#endif


#include "Ssl.h"
#include "SslOptions.h"


// libmonit
#include "system/Command.h"
#include "system/Process.h"
#include "util/Str.h"
#include "util/StringBuffer.h"
#include "system/Link.h"
#include "thread/Thread.h"


#define MONITRC            "monitrc"
#define TIMEFORMAT         "%Z %b %e %T"
#define STRERROR            strerror(errno)
#define STRLEN             256
#ifndef USEC_PER_SEC
#define USEC_PER_SEC       1000000L
#endif
#define USEC_PER_MSEC      1000L

#define ARGMAX             64
#define MYPIDDIR           PIDDIR
#define MYPIDFILE          "monit.pid"
#define MYSTATEFILE        "monit.state"
#define MYIDFILE           "monit.id"
#define MYEVENTLISTBASE    "/var/monit"

#define LOCALHOST          "localhost"

#define PORT_SMTP          25
#define PORT_SMTPS         465
#define PORT_HTTP          80
#define PORT_HTTPS         443

#define SSL_TIMEOUT        15000
#define SMTP_TIMEOUT       30000

#define START_DELAY        0
#define EXEC_TIMEOUT       30
#define PROGRAM_TIMEOUT    300


typedef enum {
        Httpd_Start = 1,
        Httpd_Stop
} __attribute__((__packed__)) Httpd_Action;


typedef enum {
        Every_Cycle = 0,
        Every_SkipCycles,
        Every_Cron,
        Every_NotInCron
} __attribute__((__packed__)) Every_Type;


typedef enum {
        State_Succeeded = 0,
        State_Failed,
        State_Changed,
        State_ChangedNot,
        State_Init
} __attribute__((__packed__)) State_Type;


typedef enum {
        Operator_Greater = 0,
        Operator_Less,
        Operator_Equal,
        Operator_NotEqual,
        Operator_Changed
} __attribute__((__packed__)) Operator_Type;


typedef enum {
        Httpd_Disabled                    = 0x0,
        Httpd_Net                         = 0x1,  // IP
        Httpd_Unix                        = 0x2,  // Unix socket
        Httpd_Ssl                         = 0x4,  // SSL enabled
        Httpd_Signature                   = 0x8,  // Server Signature enabled
        Httpd_AllowSelfSignedCertificates = 0x10  // Server Signature enabled
} __attribute__((__packed__)) Httpd_Flags;


typedef enum {
        Time_Second = 1,
        Time_Minute = 60,
        Time_Hour   = 3600,
        Time_Day    = 86400,
        Time_Month  = 2678400
} __attribute__((__packed__)) Time_Type;


typedef enum {
        Action_Ignored = 0,
        Action_Alert,
        Action_Restart,
        Action_Stop,
        Action_Exec,
        Action_Unmonitor,
        Action_Start,
        Action_Monitor
} __attribute__((__packed__)) Action_Type;


typedef enum {
        Monitor_Active = 0,
        Monitor_Passive,
        Monitor_Manual
} __attribute__((__packed__)) Monitor_Mode;


typedef enum {
        Monitor_Not     = 0x0,
        Monitor_Yes     = 0x1,
        Monitor_Init    = 0x2,
        Monitor_Waiting = 0x4
} __attribute__((__packed__)) Monitor_State;


typedef enum {
        Service_Filesystem = 0,
        Service_Directory,
        Service_File,
        Service_Process,
        Service_Host,
        Service_System,
        Service_Fifo,
        Service_Program,
        Service_Net
} __attribute__((__packed__)) Service_Type;


typedef enum {
        Resource_CpuPercent = 1,
        Resource_MemoryPercent,
        Resource_MemoryKbyte,
        Resource_LoadAverage1m,
        Resource_LoadAverage5m,
        Resource_LoadAverage15m,
        Resource_Children,
        Resource_MemoryKbyteTotal,
        Resource_MemoryPercentTotal,
        Resource_Inode,
        Resource_Space,
        Resource_CpuUser,
        Resource_CpuSystem,
        Resource_CpuWait,
        Resource_CpuPercentTotal,
        Resource_SwapPercent,
        Resource_SwapKbyte
} __attribute__((__packed__)) Resource_Type;



typedef enum {
        Digest_Cleartext = 1,
        Digest_Crypt,
        Digest_Md5,
        Digest_Pam
} __attribute__((__packed__)) Digest_Type;


typedef enum {
        Unit_Byte     = 1,
        Unit_Kilobyte = 1024,
        Unit_Megabyte = 1048576,
        Unit_Gigabyte = 1073741824
} __attribute__((__packed__)) Unit_Type;


typedef enum {
        Hash_Unknown = 0,
        Hash_Md5,
        Hash_Sha1,
        Hash_Default = Hash_Md5
} __attribute__((__packed__)) Hash_Type;


typedef enum {
        Level_Full = 0,
        Level_Summary
} __attribute__((__packed__)) Level_Type;


typedef enum {
        Handler_Succeeded = 0x0,
        Handler_Alert     = 0x1,
        Handler_Mmonit    = 0x2,
        Handler_Max       = Handler_Mmonit
} __attribute__((__packed__)) Handler_Type;


/* Length of the longest message digest in bytes */
#define MD_SIZE 65


#define ICMP_ATTEMPT_COUNT 3


#define EXPECT_BUFFER_MAX (Unit_Kilobyte * 100 + 1)


#define LEVEL_NAME_FULL    "full"
#define LEVEL_NAME_SUMMARY "summary"


#include "socket.h"


/** ------------------------------------------------- Special purpose macros */


/* Replace the standard signal function with a more reliable using
 * sigaction. Taken from Stevens APUE book. */
typedef void Sigfunc(int);
Sigfunc *signal(int signo, Sigfunc * func);
#if defined(SIG_IGN) && !defined(SIG_ERR)
#define SIG_ERR ((Sigfunc *)-1)
#endif


/** ------------------------------------------------- General purpose macros */


#undef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#undef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#define IS(a,b)  ((a && b) ? Str_isEqual(a, b) : false)
#define DEBUG LogDebug
#define FLAG(x, y) (x & y) == y
#define NVLSTR(x) (x ? x : "")


/** ------------------------------------------ Simple Assert Exception macro */


#define ASSERT(e) do { if (!(e)) { LogCritical("AssertException: " #e \
" at %s:%d\naborting..\n", __FILE__, __LINE__); abort(); } } while (0)


/* --------------------------------------------------------- Data structures */


/** Message Digest type with size for the longest digest we will compute */
typedef char MD_T[MD_SIZE];


/**
 * Defines a Command with ARGMAX optional arguments. The arguments
 * array must be NULL terminated and the first entry is the program
 * itself. In addition, a user and group may be set for the Command
 * which means that the Command should run as a certain user and with
 * certain group.
 */
typedef struct mycommand {
        char *arg[ARGMAX];                             /**< Program with arguments */
        short length;                       /**< The length of the arguments array */
        boolean_t has_uid;      /**< true if a new uid is defined for this Command */
        boolean_t has_gid;      /**< true if a new gid is defined for this Command */
        uid_t uid;         /**< The user id to switch to when running this Command */
        gid_t gid;        /**< The group id to switch to when running this Command */
        unsigned timeout;     /**< Max seconds which we wait for method to execute */
} *command_t;


/** Defines an event action object */
typedef struct myaction {
        Action_Type id;                                   /**< Action to be done */
        unsigned char count;       /**< Event count needed to trigger the action */
        unsigned char cycles;/**< Cycles during which count limit can be reached */
        command_t exec;                     /**< Optional command to be executed */
} *Action_T;


/** Defines event's up and down actions */
typedef struct myeventaction {
        Action_T  failed;                  /**< Action in the case of failure down */
        Action_T  succeeded;                    /**< Action in the case of failure up */
} *EventAction_T;


/** Defines an url object */
typedef struct myurl {
        char *url;                                                  /**< Full URL */
        char *protocol;                                    /**< URL protocol type */
        char *user;                                        /**< URL user     part */
        char *password;                                    /**< URL password part */
        char *hostname;                                    /**< URL hostname part */
        int   port;                                        /**< URL port     part */
        char *path;                                        /**< URL path     part */
        char *query;                                       /**< URL query    part */
} *URL_T;


/** Defines a HTTP client request object */
typedef struct myrequest {
        URL_T url;                                               /**< URL request */
        Operator_Type operator;         /**< Response content comparison operator */
#ifdef HAVE_REGEX_H
        regex_t *regex;                   /* regex used to test the response body */
#else
        char *regex;                 /* string to search for in the response body */
#endif
} *Request_T;


/** Defines an event notification and status receiver object */
typedef struct mymmonit {
        URL_T url;                                             /**< URL definition */
        SslOptions_T ssl;                                      /**< SSL definition */
        int timeout;                /**< The timeout to wait for connection or i/o */

        /** For internal use */
        struct mymmonit *next;                         /**< next receiver in chain */
} *Mmonit_T;


/** Defines a mailinglist object */
typedef struct mymail {
        char *to;                         /**< Mail address for alert notification */
        char *from;                                     /**< The mail from address */
        char *replyto;                              /**< Optional reply-to address */
        char *subject;                                       /**< The mail subject */
        char *message;                                       /**< The mail message */
        unsigned int events;  /*< Events for which this mail object should be sent */
        unsigned int reminder;              /*< Send error reminder each Xth cycle */

        /** For internal use */
        struct mymail *next;                          /**< next recipient in chain */
} *Mail_T;


/** Defines a mail server address */
typedef struct mymailserver {
        char *host;     /**< Server host address, may be a IP or a hostname string */
        int   port;                                               /**< Server port */
        char *username;                               /** < Username for SMTP_AUTH */
        char *password;                               /** < Password for SMTP_AUTH */
        SslOptions_T ssl;                                      /**< SSL definition */

        /** For internal use */
        struct mymailserver *next;        /**< Next server to try on connect error */
} *MailServer_T;


typedef struct myauthentication {
        char *uname;                  /**< User allowed to connect to monit httpd */
        char *passwd;                                /**< The users password data */
        char *groupname;                                      /**< PAM group name */
        Digest_Type digesttype;                /**< How did we store the password */
        boolean_t is_readonly; /**< true if this is a read-only authenticated user*/
        struct myauthentication *next;       /**< Next credential or NULL if last */
} *Auth_T;


/** Defines process tree - data storage backend */
typedef struct myprocesstree {
        boolean_t     visited;
        boolean_t     zombie;
        pid_t         pid;
        pid_t         ppid;
        int           parent;
        int           uid;
        int           euid;
        int           gid;
        int           children_num;
        int           children_sum;
        short         cpu_percent;
        short         cpu_percent_sum;
        unsigned long mem_kbyte;
        unsigned long mem_kbyte_sum;
        time_t        starttime;
        char         *cmdline;

        /** For internal use */
        double        time;                                      /**< 1/10 seconds */
        double        time_prev;                                 /**< 1/10 seconds */
        long          cputime;                                   /**< 1/10 seconds */
        long          cputime_prev;                              /**< 1/10 seconds */

        int          *children;
} ProcessTree_T;


/** Defines data for systemwide statistic */
typedef struct mysysteminfo {
        int cpus;                                              /**< Number of CPUs */
        short total_mem_percent;       /**< Total real memory in use in the system */
        short total_swap_percent;             /**< Total swap in use in the system */
        short total_cpu_user_percent;    /**< Total CPU in use in user space (pct.)*/
        short total_cpu_syst_percent;  /**< Total CPU in use in kernel space (pct.)*/
        short total_cpu_wait_percent;       /**< Total CPU in use in waiting (pct.)*/
        unsigned long mem_kbyte_max;               /**< Maximal system real memory */
        unsigned long swap_kbyte_max;                               /**< Swap size */
        unsigned long total_mem_kbyte; /**< Total real memory in use in the system */
        unsigned long total_swap_kbyte;       /**< Total swap in use in the system */
        double loadavg[3];                                /**< Load average triple */
        struct utsname uname;        /**< Platform information provided by uname() */
        struct timeval collected;                    /**< When were data collected */
} SystemInfo_T;


/** Defines a protocol object with protocol functions */
typedef struct Protocol_T {
        const char *name;                                       /**< Protocol name */
        void (*check)(Socket_T);          /**< Protocol verification function */
} *Protocol_T;


/** Defines a send/expect object used for generic protocol tests */
typedef struct mygenericproto {
        char *send;                           /* string to send, or NULL if expect */
#ifdef HAVE_REGEX_H
        regex_t *expect;                  /* regex code to expect, or NULL if send */
#else
        char *expect;                         /* string to expect, or NULL if send */
#endif
        /** For internal use */
        struct mygenericproto *next;
} *Generic_T;

/** Defines a port object */
//FIXME: use unions for protocol-specific and sockettype-specific data
typedef struct myport {
        char *hostname;                                     /**< Hostname to check */
        List_T http_headers;    /**< Optional list of headers to send with request */
        char *request;                              /**< Specific protocol request */
        char *request_checksum;     /**< The optional checksum for a req. document */
        char *request_hostheader;/**< The optional Host: header to use. Deprecated */
        char *pathname;                   /**< Pathname, in case of an UNIX socket */
        Generic_T generic;                                /**< Generic test handle */
        volatile int socket;                       /**< Socket used for connection */
        int port;                                                  /**< Portnumber */
        Socket_Type type;           /**< Socket type used for connection (UDP/TCP) */
        Socket_Family family;    /**< Socket family used for connection (NET/UNIX) */
        Hash_Type request_hashtype; /**< The optional type of hash for a req. document */
        Operator_Type operator;                           /**< Comparison operator */
        boolean_t is_available;          /**< true if the server/port is available */
        int maxforward;            /**< Optional max forward for protocol checking */
        int timeout; /**< The timeout in millseconds to wait for connect or read i/o */
        int retry;       /**< Number of connection retry before reporting an error */
        int version;                                         /**< Protocol version */
        int status;                                           /**< Protocol status */
        double response;                      /**< Socket connection response time */
        EventAction_T action;  /**< Description of the action upon event occurence */
        /** Apache-status specific parameters */
        struct apache_status {
                short loglimit;                  /**< Max percentage of logging processes */
                short closelimit;             /**< Max percentage of closinging processes */
                short dnslimit;         /**< Max percentage of processes doing DNS lookup */
                short keepalivelimit;          /**< Max percentage of keepalive processes */
                short replylimit;               /**< Max percentage of replying processes */
                short requestlimit;     /**< Max percentage of processes reading requests */
                short startlimit;            /**< Max percentage of processes starting up */
                short waitlimit;  /**< Min percentage of processes waiting for connection */
                short gracefullimit;/**< Max percentage of processes gracefully finishing */
                short cleanuplimit;      /**< Max percentage of processes in idle cleanup */
                Operator_Type loglimitOP;                          /**< loglimit operator */
                Operator_Type closelimitOP;                      /**< closelimit operator */
                Operator_Type dnslimitOP;                          /**< dnslimit operator */
                Operator_Type keepalivelimitOP;              /**< keepalivelimit operator */
                Operator_Type replylimitOP;                      /**< replylimit operator */
                Operator_Type requestlimitOP;                  /**< requestlimit operator */
                Operator_Type startlimitOP;                      /**< startlimit operator */
                Operator_Type waitlimitOP;                        /**< waitlimit operator */
                Operator_Type gracefullimitOP;                /**< gracefullimit operator */
                Operator_Type cleanuplimitOP;                  /**< cleanuplimit operator */
        } ApacheStatus;

        SslOptions_T SSL;                                      /**< SSL definition */
        Protocol_T protocol;     /**< Protocol object for testing a port's service */
        Request_T url_request;             /**< Optional url client request object */

        /** For internal use */
        struct myport *next;                               /**< next port in chain */
} *Port_T;


/** Defines a ICMP/Ping object */
typedef struct myicmp {
        int type;                                              /**< ICMP type used */
        int count;                                   /**< ICMP echo requests count */
        int timeout;         /**< The timeout in milliseconds to wait for response */
        boolean_t is_available;               /**< true if the server is available */
        Socket_Family family;                 /**< ICMP family used for connection */
        double response;                              /**< ICMP ECHO response time */
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct myicmp *next;                               /**< next icmp in chain */
} *Icmp_T;


typedef struct myservicegroupmember {
        char *name;                                           /**< name of service */

        /** For internal use */
        struct myservicegroupmember *next;              /**< next service in chain */
} *ServiceGroupMember_T;


typedef struct myservicegroup {
        char *name;                                     /**< name of service group */
        struct myservicegroupmember *members;           /**< Service group members */

        /** For internal use */
        struct myservicegroup *next;              /**< next service group in chain */
} *ServiceGroup_T;


typedef struct mydependant {
        char *dependant;                            /**< name of dependant service */

        /** For internal use */
        struct mydependant *next;             /**< next dependant service in chain */
} *Dependant_T;


/** Defines resource data */
typedef struct myresource {
        Resource_Type resource_id;                     /**< Which value is checked */
        Operator_Type operator;                           /**< Comparison operator */
        long limit;                                     /**< Limit of the resource */
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct myresource *next;                       /**< next resource in chain */
} *Resource_T;


/** Defines timestamp object */
typedef struct mytimestamp {
        boolean_t test_changes;       /**< true if we only should test for changes */
        Operator_Type operator;                           /**< Comparison operator */
        int  time;                                        /**< Timestamp watermark */
        time_t timestamp; /**< The original last modified timestamp for this object*/
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct mytimestamp *next;                     /**< next timestamp in chain */
} *Timestamp_T;


/** Defines action rate object */
typedef struct myactionrate {
        int  count;                                            /**< Action counter */
        int  cycle;                                             /**< Cycle counter */
        EventAction_T action;    /**< Description of the action upon matching rate */

        /** For internal use */
        struct myactionrate *next;                   /**< next actionrate in chain */
} *ActionRate_T;


/** Defines when to run a check for a service. This type suports both the old
 cycle based every statement and the new cron-format version */
typedef struct myevery {
        Every_Type type; /**< 0 = not set, 1 = cycle, 2 = cron, 3 = negated cron */
        time_t last_run;
        union {
                struct {
                        int number; /**< Check this program at a given cycles */
                        int counter; /**< Counter for number. When counter == number, check */
                } cycle; /**< Old cycle based every check */
                char *cron; /* A crontab format string */
        } spec;
} Every_T;


typedef struct mystatus {
        boolean_t initialized;                 /**< true if status was initialized */
        Operator_Type operator;                           /**< Comparison operator */
        int return_value;                /**< Return value of the program to check */
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct mystatus *next;                       /**< next exit value in chain */
} *Status_T;


typedef struct myprogram {
        Process_T P;          /**< A Process_T object representing the sub-process */
        Command_T C;          /**< A Command_T object for creating the sub-process */
        command_t args;                                     /**< Program arguments */
        int timeout;           /**< Seconds the program may run until it is killed */
        time_t started;                      /**< When the sub-process was started */
        int exitStatus;                 /**< Sub-process exit status for reporting */
        StringBuffer_T output;                            /**< Last program output */
} *Program_T;


/** Defines size object */
typedef struct mysize {
        boolean_t initialized;                   /**< true if size was initialized */
        boolean_t test_changes;       /**< true if we only should test for changes */
        Operator_Type operator;                           /**< Comparison operator */
        unsigned long long size;                               /**< Size watermark */
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct mysize *next;                               /**< next size in chain */
} *Size_T;


/** Defines uptime object */
typedef struct myuptime {
        Operator_Type operator;                           /**< Comparison operator */
        unsigned long long uptime;                           /**< Uptime watermark */
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct myuptime *next;                           /**< next uptime in chain */
} *Uptime_T;


typedef struct mylinkstatus {
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct mylinkstatus *next;                      /**< next link in chain */
} *LinkStatus_T;


typedef struct mylinkspeed {
        int duplex;                                        /**< Last duplex status */
        long long speed;                                     /**< Last speed [bps] */
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct mylinkspeed *next;                       /**< next link in chain */
} *LinkSpeed_T;


typedef struct mylinksaturation {
        Operator_Type operator;                           /**< Comparison operator */
        float limit;                                     /**< Saturation limit [%] */
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct mylinksaturation *next;                  /**< next link in chain */
} *LinkSaturation_T;


typedef struct mybandwidth {
        Operator_Type operator;                           /**< Comparison operator */
        unsigned long long limit;                              /**< Data watermark */
        int rangecount;                            /**< Time range to watch: count */
        Time_Type range;                                  /**< Time range to watch: unit */
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct mybandwidth *next;                     /**< next bandwidth in chain */
} *Bandwidth_T;


/** Defines checksum object */
typedef struct mychecksum {
        boolean_t initialized;               /**< true if checksum was initialized */
        boolean_t test_changes;       /**< true if we only should test for changes */
        Hash_Type type;                   /**< The type of hash (e.g. md5 or sha1) */
        MD_T  hash;                     /**< A checksum hash computed for the path */
        int   length;                                      /**< Length of the hash */
        EventAction_T action;  /**< Description of the action upon event occurence */
} *Checksum_T;


/** Defines permission object */
typedef struct myperm {
        boolean_t test_changes;       /**< true if we only should test for changes */
        int perm;                                           /**< Access permission */
        EventAction_T action;  /**< Description of the action upon event occurence */
} *Perm_T;

/** Defines match object */
typedef struct mymatch {
        boolean_t ignore;                                        /**< Ignore match */
        boolean_t not;                                           /**< Invert match */
        char    *match_string;                                   /**< Match string */
        char    *match_path;                         /**< File with matching rules */
#ifdef HAVE_REGEX_H
        regex_t *regex_comp;                                    /**< Match compile */
#endif
        StringBuffer_T log;    /**< The temporary buffer used to record the matches */
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct mymatch *next;                             /**< next match in chain */
} *Match_T;


/** Defines uid object */
typedef struct myuid {
        uid_t     uid;                                            /**< Owner's uid */
        EventAction_T action;  /**< Description of the action upon event occurence */
} *Uid_T;


/** Defines gid object */
typedef struct mygid {
        gid_t     gid;                                            /**< Owner's gid */
        EventAction_T action;  /**< Description of the action upon event occurence */
} *Gid_T;


/** Defines pid object */
typedef struct mypid {
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct mypid *next;                                 /**< next pid in chain */
} *Pid_T;


typedef struct myfsflag {
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct myfsflag *next;
} *Fsflag_T;


typedef struct mynonexist {
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct mynonexist *next;
} *Nonexist_T;


/** Defines filesystem configuration */
typedef struct myfilesystem {
        Resource_Type resource;               /**< Whether to check inode or space */
        Operator_Type operator;                           /**< Comparison operator */
        long long limit_absolute;                          /**< Watermark - blocks */
        short limit_percent;                              /**< Watermark - percent */
        EventAction_T action;  /**< Description of the action upon event occurence */

        /** For internal use */
        struct myfilesystem *next;                   /**< next filesystem in chain */
} *Filesystem_T;


/** Defines service data */
typedef struct myinfo {
        union {
                struct {
                        long long  f_bsize;                           /**< Transfer block size */
                        long long  f_blocks;              /**< Total data blocks in filesystem */
                        long long  f_blocksfree;   /**< Free blocks available to non-superuser */
                        long long  f_blocksfreetotal;           /**< Free blocks in filesystem */
                        long long  f_files;                /**< Total file nodes in filesystem */
                        long long  f_filesfree;             /**< Free file nodes in filesystem */
                        long long  inode_total;                  /**< Used inode total objects */
                        long long  space_total;                   /**< Used space total blocks */
                        short inode_percent;                   /**< Used inode percentage * 10 */
                        short space_percent;                   /**< Used space percentage * 10 */
                        int _flags;                      /**< Filesystem flags from last cycle */
                        int flags;                     /**< Filesystem flags from actual cycle */
                        int uid;                                              /**< Owner's uid */
                        int gid;                                              /**< Owner's gid */
                        mode_t mode;                                           /**< Permission */
                } filesystem;

                struct {
                        time_t timestamp;                                       /**< Timestamp */
                        mode_t mode;                                           /**< Permission */
                        int uid;                                              /**< Owner's uid */
                        int gid;                                              /**< Owner's gid */
                        off_t size;                                                  /**< Size */
                        off_t readpos;                        /**< Position for regex matching */
                        ino_t inode;                                                /**< Inode */
                        ino_t inode_prev;               /**< Previous inode for regex matching */
                        MD_T  cs_sum;                                            /**< Checksum */
                } file;

                struct {
                        time_t timestamp;                                       /**< Timestamp */
                        mode_t mode;                                           /**< Permission */
                        int uid;                                              /**< Owner's uid */
                        int gid;                                              /**< Owner's gid */
                } directory;

                struct {
                        time_t timestamp;                                       /**< Timestamp */
                        mode_t mode;                                           /**< Permission */
                        int uid;                                              /**< Owner's uid */
                        int gid;                                              /**< Owner's gid */
                } fifo;

                struct {
                        pid_t _pid;                           /**< Process PID from last cycle */
                        pid_t _ppid;                   /**< Process parent PID from last cycle */
                        pid_t pid;                          /**< Process PID from actual cycle */
                        pid_t ppid;                  /**< Process parent PID from actual cycle */
                        int uid;                                              /**< Process UID */
                        int euid;                                   /**< Effective Process UID */
                        int gid;                                              /**< Process GID */
                        boolean_t zombie;
                        int children;
                        long mem_kbyte;
                        long total_mem_kbyte;
                        short mem_percent;                                /**< percentage * 10 */
                        short total_mem_percent;                          /**< percentage * 10 */
                        short cpu_percent;                                /**< percentage * 10 */
                        short total_cpu_percent;                          /**< percentage * 10 */
                        time_t uptime;                                     /**< Process uptime */
                } process;

                struct {
                        Link_T stats;
                } net;
        } priv;
} *Info_T;


/** Defines service data */
//FIXME: use union for type-specific rules
typedef struct myservice {

        /** Common parameters */
        char *name;                                  /**< Service descriptive name */
        boolean_t (*check)(struct myservice *); /**< Service verification function */
        boolean_t visited;      /**< Service visited flag, set if dependencies are used */
        boolean_t depend_visited;/**< Depend visited flag, set if dependencies are used */
        Service_Type type;                             /**< Monitored service type */
        Monitor_State monitor;                             /**< Monitor state flag */
        Monitor_Mode mode;                    /**< Monitoring mode for the service */
        Action_Type doaction;                 /**< Action scheduled by http thread */
        int  ncycle;                          /**< The number of the current cycle */
        int  nstart;           /**< The number of current starts with this service */
        Every_T every;              /**< Timespec for when to run check of service */
        command_t start;                    /**< The start command for the service */
        command_t stop;                      /**< The stop command for the service */
        command_t restart;                /**< The restart command for the service */
        Program_T program;                            /**< Program execution check */

        Dependant_T dependantlist;                     /**< Dependant service list */
        Mail_T      maillist;                  /**< Alert notification mailinglist */

        /** Test rules and event handlers */
        ActionRate_T actionratelist;                    /**< ActionRate check list */
        Checksum_T  checksum;                                  /**< Checksum check */
        Filesystem_T filesystemlist;                    /**< Filesystem check list */
        Icmp_T      icmplist;                                 /**< ICMP check list */
        Perm_T      perm;                                    /**< Permission check */
        Port_T      portlist;                            /**< Portnumbers to check */
        Port_T      socketlist;                         /**< Unix sockets to check */
        Resource_T  resourcelist;                          /**< Resouce check list */
        Size_T      sizelist;                                 /**< Size check list */
        Uptime_T    uptimelist;                             /**< Uptime check list */
        Match_T     matchlist;                             /**< Content Match list */
        Match_T     matchignorelist;                /**< Content Match ignore list */
        Timestamp_T timestamplist;                       /**< Timestamp check list */
        Pid_T       pidlist;                                   /**< Pid check list */
        Pid_T       ppidlist;                                 /**< PPid check list */
        Status_T    statuslist;           /**< Program execution status check list */
        Fsflag_T    fsflaglist;           /**< Action upon filesystem flags change */
        Nonexist_T  nonexistlist;  /**< Action upon test subject existence failure */
        Uid_T       uid;                                            /**< Uid check */
        Uid_T       euid;                                 /**< Effective Uid check */
        Gid_T       gid;                                            /**< Gid check */
        LinkStatus_T linkstatuslist;                 /**< Network link status list */
        LinkSpeed_T linkspeedlist;                    /**< Network link speed list */
        LinkSaturation_T linksaturationlist;     /**< Network link saturation list */
        Bandwidth_T uploadbyteslist;                  /**< Upload bytes check list */
        Bandwidth_T uploadpacketslist;              /**< Upload packets check list */
        Bandwidth_T downloadbyteslist;              /**< Download bytes check list */
        Bandwidth_T downloadpacketslist;          /**< Download packets check list */

        /** General event handlers */
        EventAction_T action_DATA;       /**< Description of the action upon event */
        EventAction_T action_EXEC;       /**< Description of the action upon event */
        EventAction_T action_INVALID;    /**< Description of the action upon event */

        /** Internal monit events */
        EventAction_T action_MONIT_START;         /**< Monit instance start action */
        EventAction_T action_MONIT_STOP;           /**< Monit instance stop action */
        EventAction_T action_MONIT_RELOAD;       /**< Monit instance reload action */
        EventAction_T action_ACTION;           /**< Action requested by CLI or GUI */

        /** Runtime parameters */
        int                error;                          /**< Error flags bitmap */
        int                error_hint;   /**< Failed/Changed hint for error bitmap */
        Info_T             inf;                          /**< Service check result */
        struct timeval     collected;                /**< When were data collected */
        char              *token;                                /**< Action token */

        /** Events */
        struct myevent {
                #define           EVENT_VERSION  4      /**< The event structure version */
                long              id;                      /**< The event identification */
                struct timeval    collected;                 /**< When the event occured */
                char             *source;                 /**< Event source service name */
                Monitor_Mode      mode;             /**< Monitoring mode for the service */
                Service_Type      type;                      /**< Monitored service type */
                State_Type        state;                                 /**< Test state */
                boolean_t         state_changed;              /**< true if state changed */
                Handler_Type      flag;                     /**< The handlers state flag */
                long long         state_map;           /**< Event bitmap for last cycles */
                unsigned int      count;                             /**< The event rate */
                char             *message;    /**< Optional message describing the event */
                EventAction_T     action;           /**< Description of the event action */
                /** For internal use */
                struct myevent   *next;                         /**< next event in chain */
        } *eventlist;                                     /**< Pending events list */

        /** Context specific parameters */
        char *path;  /**< Path to the filesys, file, directory or process pid file */

        /** For internal use */
        Mutex_T mutex;                  /**< Mutex used for action synchronization */
        struct myservice *next;                         /**< next service in chain */
        struct myservice *next_conf;      /**< next service according to conf file */
        struct myservice *next_depend;           /**< next depend service in chain */
} *Service_T;


typedef struct myevent *Event_T;


/** Defines data for application runtime */
struct myrun {
        //FIXME: create enum for Run flags and replace set of various boolean_t single-purpose flags with common flags where possible
        char debug;                                               /**< Debug level */
        boolean_t once;                                  /**< true - run only once */
        boolean_t init;              /**< true - don't background to run from init */
        boolean_t isdaemon;            /**< true if program should run as a daemon */
        boolean_t use_syslog;                     /**< If true write log to syslog */
        boolean_t dolog;  /**< true if program should log actions, otherwise false */
        boolean_t fipsEnabled;          /** true if monit should use FIPS-140 mode */
        boolean_t handler_init;             /**< The handlers queue initialization */
        boolean_t doprocess;            /**< true if process status engine is used */
        boolean_t doaction;        /**< true if some service(s) has action pending */
        boolean_t dommonitcredentials; /**< true if M/Monit should receive credentials */
        volatile boolean_t stopped; /**< true if monit was stopped. Flag used by threads */
        volatile boolean_t doreload; /**< true if a monit daemon should reinitialize */
        volatile boolean_t dowakeup; /**< true if a monit daemon was wake up by signal */
        Handler_Type handler_flag;                    /**< The handlers state flag */
        //FIXME: move files to sub-struct
        char *controlfile;                /**< The file to read configuration from */
        char *logfile;                         /**< The file to write logdata into */
        char *pidfile;                                  /**< This programs pidfile */
        char *idfile;                           /**< The file with unique monit id */
        char *statefile;                /**< The file with the saved runtime state */
        char *mygroup;                              /**< Group Name of the Service */
        MD_T id;                                              /**< Unique monit id */
        int  polltime;        /**< In deamon mode, the sleeptime (sec) between run */
        int  startdelay;                    /**< the sleeptime (sec) after startup */
        int  facility;              /** The facility to use when running openlog() */
        int  eventlist_slots;          /**< The event queue size - number of slots */
        int  expectbuffer; /**< Generic protocol expect buffer - STRLEN by default */
        int mailserver_timeout; /**< Connect and read timeout ms for a SMTP server */
        time_t incarnation;              /**< Unique ID for running monit instance */
        int  handler_queue[Handler_Max + 1];       /**< The handlers queue counter */
        Service_T system;                          /**< The general system service */
        char *eventlist_dir;                   /**< The event queue base directory */

        /** An object holding Monit HTTP interface setup */
        struct {
                Httpd_Flags flags;
                union {
                        struct {
                                int  port;
                                char *address;
                                struct {
                                        char *pem;
                                        char *clientpem;
                                } ssl;
                        } net;
                        struct {
                                char *path;
                        } unix;
                } socket;
                Auth_T credentials;
        } httpd;

        /** An object holding program relevant "environment" data, see: env.c */
        struct myenvironment {
                char *user;             /**< The the effective user running this program */
                char *home;                                    /**< Users home directory */
                char *cwd;                                /**< Current working directory */
        } Env;

        char *mail_hostname;    /**< Used in HELO/EHLO/MessageID when sending mail */
        Mail_T maillist;                /**< Global alert notification mailinglist */
        MailServer_T mailservers;    /**< List of MTAs used for alert notification */
        Mmonit_T mmonits;        /**< Event notification and status receivers list */
        Auth_T mmonitcredentials;     /**< Pointer to selected credentials or NULL */
        Event_T eventlist;              /** A list holding partialy handled events */
        /** User selected standard mail format */
        struct myformat {
                char *from;                          /**< The standard mail from address */
                char *replyto;                             /**< Optional reply-to header */
                char *subject;                            /**< The standard mail subject */
                char *message;                            /**< The standard mail message */
        } MailFormat;

        Mutex_T mutex;            /**< Mutex used for service data synchronization */
};


/* -------------------------------------------------------- Global variables */

extern const char    *prog;
extern struct myrun   Run;
extern Service_T      servicelist;
extern Service_T      servicelist_conf;
extern ServiceGroup_T servicegrouplist;
extern SystemInfo_T   systeminfo;
extern ProcessTree_T *ptree;
extern int            ptreesize;
extern ProcessTree_T *oldptree;
extern int            oldptreesize;

extern char *actionnames[];
extern char *modenames[];
extern char *checksumnames[];
extern char *operatornames[];
extern char *operatorshortnames[];
extern char *statusnames[];
extern char *servicetypes[];
extern char *pathnames[];
extern char *icmpnames[];
extern char *sslnames[];

/* ------------------------------------------------------- Public prototypes */

#include "util.h"
#include "file.h"

// libmonit
#include "system/Mem.h"


/* FIXME: move remaining prototypes into seperate header-files */

boolean_t parse(char *);
boolean_t control_service(const char *, Action_Type);
boolean_t control_service_string(const char *, const char *);
boolean_t control_service_daemon(const char *, const char *);
void  setup_dependants();
void  reset_depend();
void  spawn(Service_T, command_t, Event_T);
boolean_t status(char *);
boolean_t log_init();
void  LogEmergency(const char *, ...) __attribute__((format (printf, 1, 2)));
void  LogAlert(const char *, ...) __attribute__((format (printf, 1, 2)));
void  LogCritical(const char *, ...) __attribute__((format (printf, 1, 2)));
void  LogError(const char *, ...) __attribute__((format (printf, 1, 2)));
void  LogWarning(const char *, ...) __attribute__((format (printf, 1, 2)));
void  LogNotice(const char *, ...) __attribute__((format (printf, 1, 2)));
void  LogInfo(const char *, ...) __attribute__((format (printf, 1, 2)));
void  LogDebug(const char *, ...) __attribute__((format (printf, 1, 2)));
void  vLogError(const char *s, va_list ap);
void  vLogAbortHandler(const char *s, va_list ap);
void  log_close();
#ifndef HAVE_VSYSLOG
#ifdef HAVE_SYSLOG
void vsyslog (int, const char *, va_list);
#endif /* HAVE_SYSLOG */
#endif /* HAVE_VSYSLOG */
int   validate();
void  daemonize();
void  gc();
void  gc_mail_list(Mail_T *);
void  gccmd(command_t *);
void  gc_event(Event_T *e);
boolean_t kill_daemon(int);
int   exist_daemon();
boolean_t sendmail(Mail_T);
int   sock_msg(int, char *, ...) __attribute__((format (printf, 2, 3)));
void  init_env();
void  monit_http(Httpd_Action);
boolean_t can_http();
char *format(const char *, va_list, long *);
void  redirect_stdfd();
void  fd_close();
pid_t getpgid(pid_t);
void set_signal_block(sigset_t *, sigset_t *);
boolean_t check_process(Service_T);
boolean_t check_filesystem(Service_T);
boolean_t check_file(Service_T);
boolean_t check_directory(Service_T);
boolean_t check_remote_host(Service_T);
boolean_t check_system(Service_T);
boolean_t check_fifo(Service_T);
boolean_t check_program(Service_T);
boolean_t check_net(Service_T);
int  check_URL(Service_T s);
int  sha_md5_stream (FILE *, void *, void *);
void reset_procinfo(Service_T);
int  check_service_status(Service_T);
void printhash(char *);
void status_xml(StringBuffer_T, Event_T, Level_Type, int, const char *);
Handler_Type handle_mmonit(Event_T);
boolean_t  do_wakeupcall();

#endif
