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


%{

/*
 * DESCRIPTION
 *   Simple context-free grammar for parsing the control file.
 *
 */

#include "config.h"

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ASM_PARAM_H
#include <asm/param.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#include "net.h"
#include "monit.h"
#include "protocol.h"
#include "engine.h"
#include "alert.h"
#include "process.h"
#include "device.h"

// libmonit
#include "io/File.h"
#include "util/Str.h"
#include "thread/Thread.h"


/* ------------------------------------------------------------- Definitions */

struct IHavePrecedence {
        boolean_t daemon;
        boolean_t logfile;
        boolean_t pidfile;
};

struct myrate {
        unsigned count;
        unsigned cycles;
};

/* yacc interface */
void  yyerror(const char *,...);
void  yyerror2(const char *,...);
void  yywarning(const char *,...);
void  yywarning2(const char *,...);

/* lexer interface */
int yylex(void);
extern FILE *yyin;
extern int lineno;
extern int arglineno;
extern char *yytext;
extern char *argyytext;
extern char *currentfile;
extern char *argcurrentfile;
extern int buffer_stack_ptr;

/* Local variables */
static int cfg_errflag = 0;
static Service_T tail = NULL;
static Service_T current = NULL;
static Request_T urlrequest = NULL;
static command_t command = NULL;
static command_t command1 = NULL;
static command_t command2 = NULL;
static Service_T depend_list = NULL;
static struct myuid uidset;
static struct mygid gidset;
static struct mypid pidset;
static struct mypid ppidset;
static struct myfsflag fsflagset;
static struct mynonexist nonexistset;
static struct mystatus statusset;
static struct myperm permset;
static struct mysize sizeset;
static struct myuptime uptimeset;
static struct mylinkstatus linkstatusset;
static struct mylinkspeed linkspeedset;
static struct mylinksaturation linksaturationset;
static struct mybandwidth bandwidthset;
static struct mymatch matchset;
static struct myicmp icmpset;
static struct mymail mailset;
static struct myport portset;
static struct mymailserver mailserverset;
static struct myfilesystem filesystemset;
static struct myresource resourceset;
static struct mychecksum checksumset;
static struct mytimestamp timestampset;
static struct myactionrate actionrateset;
static struct IHavePrecedence ihp = {false, false, false};
static struct myrate rate1 = {1, 1};
static struct myrate rate2 = {1, 1};
static char * htpasswd_file = NULL;
static Digest_Type digesttype = Digest_Cleartext;

#define BITMAP_MAX (sizeof(long long) * 8)


/* -------------------------------------------------------------- Prototypes */

static void  preparse();
static void  postparse();
static void  addmail(char *, Mail_T, Mail_T *);
static Service_T createservice(Service_Type, char *, char *, boolean_t (*)(Service_T));
static void  addservice(Service_T);
static void  adddependant(char *);
static void  addservicegroup(char *);
static void  addport(Port_T *, Port_T);
static void  addresource(Resource_T);
static void  addtimestamp(Timestamp_T, boolean_t);
static void  addactionrate(ActionRate_T);
static void  addsize(Size_T);
static void  adduptime(Uptime_T);
static void  addpid(Pid_T);
static void  addppid(Pid_T);
static void  addfsflag(Fsflag_T);
static void  addnonexist(Nonexist_T);
static void  addlinkstatus(Service_T, LinkStatus_T);
static void  addlinkspeed(Service_T, LinkSpeed_T);
static void  addlinksaturation(Service_T, LinkSaturation_T);
static void  addbandwidth(Bandwidth_T *, Bandwidth_T);
static void  addfilesystem(Filesystem_T);
static void  addicmp(Icmp_T);
static void  addgeneric(Port_T, char*, char*);
static void  addcommand(int, unsigned);
static void  addargument(char *);
static void  addmmonit(URL_T, int, Ssl_Version, char *);
static void  addmailserver(MailServer_T);
static boolean_t addcredentials(char *, char *, Digest_Type, boolean_t);
#ifdef HAVE_LIBPAM
static void  addpamauth(char *, int);
#endif
static void  addhtpasswdentry(char *, char *, Digest_Type);
static uid_t get_uid(char *, uid_t);
static gid_t get_gid(char *, gid_t);
static void  addchecksum(Checksum_T);
static void  addperm(Perm_T);
static void  addmatch(Match_T, int, int);
static void  addmatchpath(Match_T, Action_Type);
static void  addstatus(Status_T);
static Uid_T adduid(Uid_T);
static Gid_T addgid(Gid_T);
static void  addeuid(uid_t);
static void  addegid(gid_t);
static void  addeventaction(EventAction_T *, Action_Type, Action_Type);
static void  prepare_urlrequest(URL_T U);
static void  seturlrequest(int, char *);
static void  setlogfile(char *);
static void  setpidfile(char *);
static void  reset_mailset();
static void  reset_mailserverset();
static void  reset_portset();
static void  reset_resourceset();
static void  reset_timestampset();
static void  reset_actionrateset();
static void  reset_sizeset();
static void  reset_uptimeset();
static void  reset_pidset();
static void  reset_ppidset();
static void  reset_fsflagset();
static void  reset_nonexistset();
static void  reset_linkstatusset();
static void  reset_linkspeedset();
static void  reset_linksaturationset();
static void  reset_bandwidthset();
static void  reset_checksumset();
static void  reset_permset();
static void  reset_uidset();
static void  reset_gidset();
static void  reset_statusset();
static void  reset_filesystemset();
static void  reset_icmpset();
static void  reset_rateset();
static void  check_name(char *);
static int   check_perm(int);
static void  check_hostname (char *);
static void  check_exec(char *);
static int   cleanup_hash_string(char *);
static void  check_depend();
static void  setsyslog(char *);
static command_t copycommand(command_t);
static int verifyMaxForward(int);

%}

%union {
        URL_T url;
        float real;
        int   number;
        char *string;
}

%token IF ELSE THEN OR FAILED
%token SET LOGFILE FACILITY DAEMON SYSLOG MAILSERVER HTTPD ALLOW ADDRESS INIT
%token READONLY CLEARTEXT MD5HASH SHA1HASH CRYPT DELAY
%token PEMFILE ENABLE DISABLE HTTPDSSL CLIENTPEMFILE ALLOWSELFCERTIFICATION
%token INTERFACE LINK PACKET ERROR BYTEIN BYTEOUT PACKETIN PACKETOUT SPEED SATURATION UPLOAD DOWNLOAD TOTAL
%token IDFILE STATEFILE SEND EXPECT EXPECTBUFFER CYCLE COUNT REMINDER
%token PIDFILE START STOP PATHTOK
%token HOST HOSTNAME PORT IPV4 IPV6 TYPE UDP TCP TCPSSL PROTOCOL CONNECTION
%token ALERT NOALERT MAILFORMAT UNIXSOCKET SIGNATURE
%token TIMEOUT RETRY RESTART CHECKSUM EVERY NOTEVERY
%token DEFAULT HTTP HTTPS APACHESTATUS FTP SMTP SMTPS POP POPS IMAP IMAPS CLAMAV NNTP NTP3 MYSQL DNS WEBSOCKET
%token SSH DWP LDAP2 LDAP3 RDATE RSYNC TNS PGSQL POSTFIXPOLICY SIP LMTP GPS RADIUS MEMCACHE REDIS MONGODB SIEVE
%token <string> STRING PATH MAILADDR MAILFROM MAILREPLYTO MAILSUBJECT
%token <string> MAILBODY SERVICENAME STRINGNAME
%token <number> NUMBER PERCENT LOGLIMIT CLOSELIMIT DNSLIMIT KEEPALIVELIMIT
%token <number> REPLYLIMIT REQUESTLIMIT STARTLIMIT WAITLIMIT GRACEFULLIMIT
%token <number> CLEANUPLIMIT
%token <real> REAL
%token CHECKPROC CHECKFILESYS CHECKFILE CHECKDIR CHECKHOST CHECKSYSTEM CHECKFIFO CHECKPROGRAM CHECKNET
%token CHILDREN SYSTEM STATUS ORIGIN VERSIONOPT
%token RESOURCE MEMORY TOTALMEMORY LOADAVG1 LOADAVG5 LOADAVG15 SWAP
%token MODE ACTIVE PASSIVE MANUAL CPU TOTALCPU CPUUSER CPUSYSTEM CPUWAIT
%token GROUP REQUEST DEPENDS BASEDIR SLOT EVENTQUEUE SECRET HOSTHEADER
%token UID EUID GID MMONIT INSTANCE USERNAME PASSWORD
%token TIMESTAMP CHANGED SECOND MINUTE HOUR DAY MONTH
%token SSLAUTO SSLV2 SSLV3 TLSV1 TLSV11 TLSV12 CERTMD5
%token BYTE KILOBYTE MEGABYTE GIGABYTE
%token INODE SPACE PERMISSION SIZE MATCH NOT IGNORE ACTION UPTIME
%token EXEC UNMONITOR PING PING4 PING6 ICMP ICMPECHO NONEXIST EXIST INVALID DATA RECOVERED PASSED SUCCEEDED
%token URL CONTENT PID PPID FSFLAG
%token REGISTER CREDENTIALS
%token <url> URLOBJECT
%token <string> TARGET TIMESPEC HTTPHEADER
%token <number> MAXFORWARD
%token FIPS

%left GREATER LESS EQUAL NOTEQUAL


%%
cfgfile         : /* EMPTY */
                | statement_list
                ;

statement_list  : statement
                | statement_list statement
                ;

statement       : setalert
                | setdaemon
                | setlog
                | seteventqueue
                | setmmonits
                | setmailservers
                | setmailformat
                | sethttpd
                | setpid
                | setidfile
                | setstatefile
                | setexpectbuffer
                | setinit
                | setfips
                | checkproc optproclist
                | checkfile optfilelist
                | checkfilesys optfilesyslist
                | checkdir optdirlist
                | checkhost opthostlist
                | checksystem optsystemlist
                | checkfifo optfifolist
                | checkprogram optstatuslist
                | checknet optnetlist
                ;

optproclist     : /* EMPTY */
                | optproclist optproc
                ;

optproc         : start
                | stop
                | restart
                | exist
                | pid
                | ppid
                | uid
                | euid
                | gid
                | uptime
                | connection
                | connectionunix
                | actionrate
                | alert
                | every
                | mode
                | group
                | depend
                | resourceprocess
                ;

optfilelist      : /* EMPTY */
                | optfilelist optfile
                ;

optfile         : start
                | stop
                | restart
                | exist
                | timestamp
                | actionrate
                | every
                | alert
                | permission
                | uid
                | gid
                | checksum
                | size
                | match
                | mode
                | group
                | depend
                ;

optfilesyslist  : /* EMPTY */
                | optfilesyslist optfilesys
                ;

optfilesys      : start
                | stop
                | restart
                | actionrate
                | every
                | alert
                | permission
                | uid
                | gid
                | mode
                | group
                | depend
                | inode
                | space
                | fsflag
                ;

optdirlist      : /* EMPTY */
                | optdirlist optdir
                ;

optdir          : start
                | stop
                | restart
                | exist
                | timestamp
                | actionrate
                | every
                | alert
                | permission
                | uid
                | gid
                | mode
                | group
                | depend
                ;

opthostlist     : opthost
                | opthostlist opthost
                ;

opthost         : start
                | stop
                | restart
                | connection
                | icmp
                | actionrate
                | alert
                | every
                | mode
                | group
                | depend
                ;

optnetlist      : /* EMPTY */
                | optnetlist optnet
                ;

optnet          : start
                | stop
                | restart
                | linkstatus
                | linkspeed
                | linksaturation
                | upload
                | download
                | actionrate
                | every
                | alert
                | group
                | depend
                ;

optsystemlist   : /* EMPTY */
                | optsystemlist optsystem
                ;

optsystem       : start
                | stop
                | restart
                | actionrate
                | alert
                | every
                | group
                | depend
                | resourcesystem
                ;

optfifolist     : /* EMPTY */
                | optfifolist optfifo
                ;

optfifo         : start
                | stop
                | restart
                | exist
                | timestamp
                | actionrate
                | every
                | alert
                | permission
                | uid
                | gid
                | mode
                | group
                | depend
                ;

optstatuslist   : /* EMPTY */
                | optstatuslist optstatus
                ;

optstatus       : start
                | stop
                | restart
                | actionrate
                | alert
                | every
                | group
                | depend
                | statusvalue
                ;

setalert        : SET alertmail formatlist reminder {
                   mailset.events = Event_All;
                    addmail($<string>2, &mailset, &Run.maillist);
                  }
                | SET alertmail '{' eventoptionlist '}' formatlist reminder {
                    addmail($<string>2, &mailset, &Run.maillist);
                  }
                | SET alertmail NOT '{' eventoptionlist '}' formatlist reminder {
                   mailset.events = ~mailset.events;
                   addmail($<string>2, &mailset, &Run.maillist);
                  }
                ;

setdaemon       : SET DAEMON NUMBER startdelay {
                    if (! Run.isdaemon || ihp.daemon) {
                      ihp.daemon     = true;
                      Run.isdaemon   = true;
                      Run.polltime   = $3;
                      Run.startdelay = $<number>4;
                    }
                  }
                ;

startdelay      : /* EMPTY */        { $<number>$ = START_DELAY; }
                | START DELAY NUMBER { $<number>$ = $3; }
                ;

setexpectbuffer : SET EXPECTBUFFER NUMBER unit {
                    Run.expectbuffer = $3 * $<number>4;
                    if (Run.expectbuffer > EXPECT_BUFFER_MAX)
                        yyerror("Maximum value for expect buffer is 100 KB");
                  }
                ;

setinit         : SET INIT {
                    Run.init = true;
                  }
                ;

setfips         : SET FIPS {
                    Run.fipsEnabled = true;
                  }
                ;

setlog          : SET LOGFILE PATH   {
                   if (! Run.logfile || ihp.logfile) {
                     ihp.logfile = true;
                     setlogfile($3);
                     Run.use_syslog = false;
                     Run.dolog = true;
                   }
                  }
                | SET LOGFILE SYSLOG {
                    setsyslog(NULL);
                  }
                | SET LOGFILE SYSLOG FACILITY STRING {
                    setsyslog($5); FREE($5);
                  }
                ;

seteventqueue   : SET EVENTQUEUE BASEDIR PATH {
                    Run.eventlist_dir = $4;
                  }
                | SET EVENTQUEUE BASEDIR PATH SLOT NUMBER {
                    Run.eventlist_dir = $4;
                    Run.eventlist_slots = $6;
                  }
                | SET EVENTQUEUE SLOT NUMBER {
                    Run.eventlist_dir = Str_dup(MYEVENTLISTBASE);
                    Run.eventlist_slots = $4;
                  }
                ;

setidfile       : SET IDFILE PATH {
                    Run.idfile = $3;
                  }
                ;

setstatefile    : SET STATEFILE PATH {
                    Run.statefile = $3;
                  }
                ;

setpid          : SET PIDFILE PATH {
                   if (! Run.pidfile || ihp.pidfile) {
                     ihp.pidfile = true;
                     setpidfile($3);
                   }
                 }
                ;

setmmonits      : SET MMONIT mmonitlist
                ;

mmonitlist      : mmonit credentials
                | mmonitlist mmonit credentials
                ;

mmonit          : URLOBJECT nettimeout sslversion certmd5 {
                    check_hostname(($<url>1)->hostname);
                    addmmonit($<url>1, $<number>2, $<number>3, $<string>4);
                  }
                ;

credentials     : /* EMPTY */
                | REGISTER CREDENTIALS {
                    Run.dommonitcredentials = false;
                  }
                ;

setmailservers  : SET MAILSERVER mailserverlist nettimeout hostname {
                   if (($<number>4) > SMTP_TIMEOUT)
                     Run.mailserver_timeout = $<number>4;
                   Run.mail_hostname = $<string>5;
                  }
                ;

setmailformat   : SET MAILFORMAT '{' formatoptionlist '}' {
                   Run.MailFormat.from    = mailset.from    ?  mailset.from    : Str_dup(ALERT_FROM);
                   Run.MailFormat.replyto = mailset.replyto ?  mailset.replyto : NULL;
                   Run.MailFormat.subject = mailset.subject ?  mailset.subject : Str_dup(ALERT_SUBJECT);
                   Run.MailFormat.message = mailset.message ?  mailset.message : Str_dup(ALERT_MESSAGE);
                   reset_mailset();
                 }
                ;

mailserverlist  : mailserver
                | mailserverlist mailserver
                ;

mailserver      : STRING username password sslversion certmd5 {
                    /* Restore the current text overriden by lookahead */
                    FREE(argyytext);
                    argyytext = Str_dup($1);

                    check_hostname($1);
                    mailserverset.host = $1;
                    mailserverset.username = $<string>2;
                    mailserverset.password = $<string>3;
                    mailserverset.ssl.version = $<number>4;
                    if (mailserverset.ssl.version != SSL_Disabled) {
                      mailserverset.ssl.use_ssl = true;
                      if (mailserverset.ssl.version == SSL_V2 || mailserverset.ssl.version == SSL_V3)
                         mailserverset.port = PORT_SMTPS;
                      mailserverset.ssl.certmd5 = $<string>5;
                    }
                    addmailserver(&mailserverset);
                  }
                | STRING PORT NUMBER username password sslversion certmd5 {
                    /* Restore the current text overriden by lookahead */
                    FREE(argyytext);
                    argyytext = Str_dup($1);

                    check_hostname($1);
                    mailserverset.host = $1;
                    mailserverset.port = $<number>3;
                    mailserverset.username = $<string>4;
                    mailserverset.password = $<string>5;
                    mailserverset.ssl.version = $<number>6;
                    if (mailserverset.ssl.version != SSL_Disabled) {
                      mailserverset.ssl.use_ssl = true;
                      mailserverset.ssl.certmd5 = $<string>7;
                    }
                    addmailserver(&mailserverset);
                  }
                ;

sethttpd        : SET HTTPD PORT NUMBER httpdnetlist {
                        Run.httpd.flags |= Httpd_Net;
                        Run.httpd.socket.net.port = $4;
                 }
                | SET HTTPD UNIXSOCKET PATH httpdunixlist {
                        Run.httpd.flags |= Httpd_Unix;
                        Run.httpd.socket.unix.path = $4;
                 }
                ;

httpdnetlist    : /* EMPTY */
                | httpdnetlist httpdnetoption
                ;

httpdnetoption  : ssl
                | signature
                | bindaddress
                | allow
                ;

httpdunixlist   : /* EMPTY */
                | httpdunixlist httpdunixoption
                ;

httpdunixoption : signature
                | allow
                ;

ssl             : ssldisable optssllist {
                        Run.httpd.flags &= ~Httpd_Ssl;
                  }
                | sslenable optssllist {
                        Run.httpd.flags |= Httpd_Ssl;
#ifdef HAVE_OPENSSL
                        if (! Run.httpd.socket.net.ssl.pem)
                                yyerror("SSL server PEM file is required (pemfile option)");
                        else if (! file_checkStat(Run.httpd.socket.net.ssl.pem, "SSL server PEM file", S_IRWXU))
                                yyerror("SSL server PEM file permissions check failed");
#else
                        yyerror("SSL is not supported");
#endif
                  }
                ;

optssllist      : /* EMPTY */
                | optssllist optssl
                ;

optssl          : pemfile
                | clientpemfile
                | allowselfcert
                ;

sslenable       : HTTPDSSL ENABLE
                | ENABLE HTTPDSSL
                ;

ssldisable      : HTTPDSSL DISABLE
                | DISABLE HTTPDSSL
                ;

signature       : sigenable  {
                        Run.httpd.flags |= Httpd_Signature;
                  }
                | sigdisable {
                        Run.httpd.flags &= ~Httpd_Signature;
                  }
                ;

sigenable       : SIGNATURE ENABLE
                | ENABLE SIGNATURE
                ;

sigdisable      : SIGNATURE DISABLE
                | DISABLE SIGNATURE
                ;

bindaddress     : ADDRESS STRING {
                        Run.httpd.socket.net.address = $2;
                  }
                ;

pemfile         : PEMFILE PATH {
                        Run.httpd.socket.net.ssl.pem = $2;
                  }
                ;

clientpemfile   : CLIENTPEMFILE PATH {
                        Run.httpd.socket.net.ssl.clientpem = $2;
                        if (! file_checkStat(Run.httpd.socket.net.ssl.clientpem, "SSL client PEM file", S_IRWXU | S_IRGRP | S_IROTH))
                                yyerror2("SSL client PEM file has too loose permissions");
                  }
                ;

allowselfcert   : ALLOWSELFCERTIFICATION {
                        Run.httpd.flags |= Httpd_AllowSelfSignedCertificates;
                  }
                ;

allow           : ALLOW STRING':'STRING readonly {
                        addcredentials($2, $4, Digest_Cleartext, $<number>5);
                  }
                | ALLOW '@'STRING readonly {
#ifdef HAVE_LIBPAM
                        addpamauth($3, $<number>4);
#else
                        yyerror("PAM is not supported");
                        FREE($3);
#endif
                  }
                | ALLOW PATH {
                        addhtpasswdentry($2, NULL, Digest_Cleartext);
                        FREE($2);
                  }
                | ALLOW CLEARTEXT PATH {
                        addhtpasswdentry($3, NULL, Digest_Cleartext);
                        FREE($3);
                  }
                | ALLOW MD5HASH PATH {
                        addhtpasswdentry($3, NULL, Digest_Md5);
                        FREE($3);
                  }
                | ALLOW CRYPT PATH {
                        addhtpasswdentry($3, NULL, Digest_Crypt);
                        FREE($3);
                  }
                | ALLOW PATH {
                        htpasswd_file = $2;
                        digesttype = Digest_Cleartext;
                  }
                  allowuserlist {
                        FREE(htpasswd_file);
                  }
                | ALLOW CLEARTEXT PATH {
                        htpasswd_file = $3;
                        digesttype = Digest_Cleartext;
                  }
                  allowuserlist {
                        FREE(htpasswd_file);
                  }
                | ALLOW MD5HASH PATH {
                        htpasswd_file = $3;
                        digesttype = Digest_Md5;
                  }
                  allowuserlist {
                        FREE(htpasswd_file);
                  }
                | ALLOW CRYPT PATH {
                        htpasswd_file = $3;
                        digesttype = Digest_Crypt;
                  }
                  allowuserlist {
                        FREE(htpasswd_file);
                  }
                | ALLOW STRING {
                        if (! (Engine_addNetAllow($2) || Engine_addHostAllow($2)))
                                yyerror2("Erroneous network or host identifier %s", $2);
                        FREE($2);
                  }
                ;

allowuserlist   : allowuser
                | allowuserlist allowuser
                ;

allowuser       : STRING {
                        addhtpasswdentry(htpasswd_file, $1, digesttype);
                        FREE($1);
                  }
                ;

readonly        : /* EMPTY */ { $<number>$ = false; }
                | READONLY { $<number>$ = true; }
                ;

checkproc       : CHECKPROC SERVICENAME PIDFILE PATH {
                    createservice(Service_Process, $<string>2, $4, check_process);
                  }
                | CHECKPROC SERVICENAME PATHTOK PATH {
                    createservice(Service_Process, $<string>2, $4, check_process);
                  }
                | CHECKPROC SERVICENAME MATCH STRING {
                    createservice(Service_Process, $<string>2, $4, check_process);
                    matchset.ignore = false;
                    matchset.match_path = NULL;
                    matchset.match_string = Str_dup($4);
                    addmatch(&matchset, Action_Ignored, 0);
                  }
                | CHECKPROC SERVICENAME MATCH PATH {
                    createservice(Service_Process, $<string>2, $4, check_process);
                    matchset.ignore = false;
                    matchset.match_path = NULL;
                    matchset.match_string = Str_dup($4);
                    addmatch(&matchset, Action_Ignored, 0);
                  }
                ;

checkfile       : CHECKFILE SERVICENAME PATHTOK PATH {
                    createservice(Service_File, $<string>2, $4, check_file);
                  }
                ;

checkfilesys    : CHECKFILESYS SERVICENAME PATHTOK PATH {
                    createservice(Service_Filesystem, $<string>2, $4, check_filesystem);
                  }
                | CHECKFILESYS SERVICENAME PATHTOK STRING {
                    createservice(Service_Filesystem, $<string>2, $4, check_filesystem);
                  }
                ;

checkdir        : CHECKDIR SERVICENAME PATHTOK PATH {
                    createservice(Service_Directory, $<string>2, $4, check_directory);
                  }
                ;

checkhost       : CHECKHOST SERVICENAME ADDRESS STRING {
                    check_hostname($4);
                    createservice(Service_Host, $<string>2, $4, check_remote_host);
                  }
                ;

checknet        : CHECKNET SERVICENAME ADDRESS STRING {
                    if (Link_isGetByAddressSupported()) {
                        createservice(Service_Net, $<string>2, $4, check_net);
                        current->inf->priv.net.stats = Link_createForAddress($4);
                    } else {
                        yyerror("Network monitoring by IP address is not supported on this platform, please use 'check network <foo> with interface <bar>' instead");
                    }
                  }
                | CHECKNET SERVICENAME INTERFACE STRING {
                    createservice(Service_Net, $<string>2, $4, check_net);
                    current->inf->priv.net.stats = Link_createForInterface($4);
                  }
                ;

checksystem     : CHECKSYSTEM SERVICENAME {
                    char hostname[STRLEN];
                    if (Util_getfqdnhostname(hostname, sizeof(hostname))) {
                      LogError("Cannot get system hostname\n");
                      cfg_errflag++;
                    }
                    char *servicename = $<string>2;
                    Util_replaceString(&servicename, "$HOST", hostname);
                    Run.system = createservice(Service_System, servicename, Str_dup(""), check_system); // The name given in the 'check system' statement overrides system hostname
                  }
                ;

checkfifo       : CHECKFIFO SERVICENAME PATHTOK PATH {
                    createservice(Service_Fifo, $<string>2, $4, check_fifo);
                  }
                ;

checkprogram    : CHECKPROGRAM SERVICENAME PATHTOK argumentlist programtimeout {
                        command_t c = command; // Current command
                        check_exec(c->arg[0]);
                        createservice(Service_Program, $<string>2, Str_dup(c->arg[0]), check_program);
                        current->program->timeout = $<number>5;
                        current->program->output = StringBuffer_create(64);
                 }
                | CHECKPROGRAM SERVICENAME PATHTOK argumentlist useroptionlist programtimeout {
                        command_t c = command; // Current command
                        check_exec(c->arg[0]);
                        createservice(Service_Program, $<string>2, Str_dup(c->arg[0]), check_program);
                        current->program->timeout = $<number>5;
                        current->program->output = StringBuffer_create(64);
                 }
                ;

start           : START argumentlist exectimeout {
                    addcommand(START, $<number>3);
                  }
                | START argumentlist useroptionlist exectimeout {
                    addcommand(START, $<number>4);
                  }
                ;

stop            : STOP argumentlist exectimeout {
                    addcommand(STOP, $<number>3);
                  }
                | STOP argumentlist useroptionlist exectimeout {
                    addcommand(STOP, $<number>4);
                  }
                ;


restart         : RESTART argumentlist exectimeout {
                    addcommand(RESTART, $<number>3);
                  }
                | RESTART argumentlist useroptionlist exectimeout {
                    addcommand(RESTART, $<number>4);
                  }
                ;

argumentlist    : argument
                | argumentlist argument
                ;

useroptionlist  : useroption
                | useroptionlist useroption
                ;

argument        : STRING { addargument($1); }
                | PATH   { addargument($1); }
                ;

useroption      : UID STRING { addeuid( get_uid($2, 0) ); FREE($2); }
                | GID STRING { addegid( get_gid($2, 0) ); FREE($2); }
                | UID NUMBER { addeuid( get_uid(NULL, $2) ); }
                | GID NUMBER { addegid( get_gid(NULL, $2) ); }
                ;

username        : /* EMPTY */     { $<string>$ = NULL; }
                | USERNAME MAILADDR { $<string>$ = $2; }
                | USERNAME STRING { $<string>$ = $2; }
                ;

password        : /* EMPTY */     { $<string>$ = NULL; }
                | PASSWORD STRING { $<string>$ = $2; }
                ;

hostname        : /* EMPTY */     { $<string>$ = NULL; }
                | HOSTNAME STRING { $<string>$ = $2; }
                ;

connection      : IF FAILED host port ip type protocol urloption nettimeout retry rate1 THEN action1 recovery {
                    portset.timeout = $<number>9;
                    portset.retry = $<number>10;
                    /* This is a workaround to support content match without having to create an URL object. 'urloption' creates the Request_T object we need minus the URL object, but with enough information to perform content test.
                     TODO: Parser is in need of refactoring */
                    portset.url_request = urlrequest;
                    addeventaction(&(portset).action, $<number>13, $<number>14);
                    addport(&(current->portlist), &portset);
                  }
                | IF FAILED URL URLOBJECT urloption nettimeout retry rate1 THEN action1 recovery {
                    prepare_urlrequest($<url>4);
                    portset.timeout = $<number>6;
                    portset.retry = $<number>7;
                    addeventaction(&(portset).action, $<number>10, $<number>11);
                    addport(&(current->portlist), &portset);
                  }
                ;

connectionunix  : IF FAILED unixsocket type protocol nettimeout retry rate1 THEN action1 recovery {
                        portset.timeout = $<number>6;
                        portset.retry = $<number>7;
                        addeventaction(&(portset).action, $<number>10, $<number>11);
                        addport(&(current->socketlist), &portset);
                  }
                ;

icmp            : IF FAILED ICMP icmptype icmpcount nettimeout rate1 THEN action1 recovery {
                        icmpset.family = Socket_Ip;
                        icmpset.type = $<number>4;
                        icmpset.count = $<number>5;
                        icmpset.timeout = $<number>6;
                        addeventaction(&(icmpset).action, $<number>9, $<number>10);
                        addicmp(&icmpset);
                  }
                | IF FAILED PING icmpcount nettimeout rate1 THEN action1 recovery {
                        icmpset.family = Socket_Ip;
                        icmpset.type = ICMP_ECHO;
                        icmpset.count = $<number>4;
                        icmpset.timeout = $<number>5;
                        addeventaction(&(icmpset).action, $<number>8, $<number>9);
                        addicmp(&icmpset);
                 }
                | IF FAILED PING4 icmpcount nettimeout rate1 THEN action1 recovery {
                        icmpset.family = Socket_Ip4;
                        icmpset.type = ICMP_ECHO;
                        icmpset.count = $<number>4;
                        icmpset.timeout = $<number>5;
                        addeventaction(&(icmpset).action, $<number>8, $<number>9);
                        addicmp(&icmpset);
                 }
                | IF FAILED PING6 icmpcount nettimeout rate1 THEN action1 recovery {
                        icmpset.family = Socket_Ip6;
                        icmpset.type = ICMP_ECHO;
                        icmpset.count = $<number>4;
                        icmpset.timeout = $<number>5;
                        addeventaction(&(icmpset).action, $<number>8, $<number>9);
                        addicmp(&icmpset);
                 }
                ;

host            : /* EMPTY */ {
                        portset.hostname = Str_dup(current->type == Service_Host ? current->path : LOCALHOST);
                  }
                | HOST STRING {
                        check_hostname($2);
                        portset.hostname = $2;
                  }
                ;

port            : PORT NUMBER {
                        portset.port = $2;
                  }
                ;

unixsocket      : UNIXSOCKET PATH {
                        portset.pathname = $2;
                        portset.family = Socket_Unix;
                  }
                ;

ip              : /* EMPTY */ {
                    portset.family = Socket_Ip;
                  }
                | IPV4 {
                    portset.family = Socket_Ip4;
                  }
                | IPV6 {
                    portset.family = Socket_Ip6;
                  }
                ;

type            : /* EMPTY */ {
                    portset.type = Socket_Tcp;
                  }
                | TYPE TCP {
                    portset.type = Socket_Tcp;
                  }
                | TYPE TCPSSL sslversion certmd5  {
                    portset.type = Socket_Tcp;
                    portset.SSL.use_ssl = true;
                    portset.SSL.version = $<number>3;
                    if (portset.SSL.version == SSL_Disabled)
                      portset.SSL.version = SSL_Auto;
                    portset.SSL.certmd5 = $<string>4;
                  }
                | TYPE UDP {
                    portset.type = Socket_Udp;
                  }
                ;

certmd5         : /* EMPTY */ {
                        $<string>$ = NULL;
                  }
                | CERTMD5 STRING {
                        $<string>$ = $2;
                  }
                ;

sslversion      : /* EMPTY */  { $<number>$ = SSL_Disabled; }
                | SSLV2        { $<number>$ = SSL_V2; }
                | SSLV3        { $<number>$ = SSL_V3; }
                | TLSV1        { $<number>$ = SSL_TLSV1; }
                | TLSV11
                {
#ifndef HAVE_TLSV1_1
                        yyerror("Your SSL Library does not support TLS version 1.1");
#endif
                        $<number>$ = SSL_TLSV11;
                }
                | TLSV12
                {
#ifndef HAVE_TLSV1_2
                        yyerror("Your SSL Library does not support TLS version 1.2");
#endif
                        $<number>$ = SSL_TLSV12;
                }
                | SSLAUTO      { $<number>$ = SSL_Auto; }
                ;

protocol        : /* EMPTY */  {
                    portset.protocol = Protocol_get(Protocol_DEFAULT);
                  }
                | PROTOCOL APACHESTATUS apache_stat_list {
                    portset.protocol = Protocol_get(Protocol_APACHESTATUS);
                  }
                | PROTOCOL DEFAULT {
                    portset.protocol = Protocol_get(Protocol_DEFAULT);
                  }
                | PROTOCOL DNS {
                    portset.protocol = Protocol_get(Protocol_DNS);
                  }
                | PROTOCOL DWP  {
                    portset.protocol = Protocol_get(Protocol_DWP);
                  }
                | PROTOCOL FTP {
                    portset.protocol = Protocol_get(Protocol_FTP);
                  }
                | PROTOCOL HTTP httplist {
                        portset.protocol = Protocol_get(Protocol_HTTP);
                  }
                | PROTOCOL HTTPS httplist {
                        portset.type = Socket_Tcp;
                        portset.SSL.use_ssl = true;
                        portset.SSL.version = SSL_Auto;
                        portset.protocol = Protocol_get(Protocol_HTTP);
                 }
                | PROTOCOL IMAP {
                        portset.protocol = Protocol_get(Protocol_IMAP);
                  }
                | PROTOCOL IMAPS {
                        portset.type = Socket_Tcp;
                        portset.SSL.use_ssl = true;
                        portset.SSL.version = SSL_Auto;
                        portset.protocol = Protocol_get(Protocol_IMAP);
                  }
                | PROTOCOL CLAMAV {
                    portset.protocol = Protocol_get(Protocol_CLAMAV);
                  }
                | PROTOCOL LDAP2 {
                    portset.protocol = Protocol_get(Protocol_LDAP2);
                  }
                | PROTOCOL LDAP3 {
                    portset.protocol = Protocol_get(Protocol_LDAP3);
                  }
                | PROTOCOL MONGODB  {
                    portset.protocol = Protocol_get(Protocol_MONGODB);
                  }
                | PROTOCOL MYSQL {
                    portset.protocol = Protocol_get(Protocol_MYSQL);
                  }
                | PROTOCOL SIP target maxforward {
                    portset.protocol = Protocol_get(Protocol_SIP);
                  }
                | PROTOCOL NNTP {
                    portset.protocol = Protocol_get(Protocol_NNTP);
                  }
                | PROTOCOL NTP3  {
                    portset.protocol = Protocol_get(Protocol_NTP3);
                    portset.type = Socket_Udp;
                  }
                | PROTOCOL POSTFIXPOLICY {
                    portset.protocol = Protocol_get(Protocol_POSTFIXPOLICY);
                  }
                | PROTOCOL POP {
                    portset.protocol = Protocol_get(Protocol_POP);
                  }
                | PROTOCOL POPS {
                    portset.type = Socket_Tcp;
                    portset.SSL.use_ssl = true;
                    portset.SSL.version = SSL_Auto;
                    portset.protocol = Protocol_get(Protocol_POP);
                  }
                | PROTOCOL SIEVE {
                    portset.protocol = Protocol_get(Protocol_SIEVE);
                  }
                | PROTOCOL SMTP {
                    portset.protocol = Protocol_get(Protocol_SMTP);
                  }
                | PROTOCOL SMTPS {
                        portset.type = Socket_Tcp;
                        portset.SSL.use_ssl = true;
                        portset.SSL.version = SSL_Auto;
                        portset.protocol = Protocol_get(Protocol_SMTP);
                 }
                | PROTOCOL SSH  {
                    portset.protocol = Protocol_get(Protocol_SSH);
                  }
                | PROTOCOL RDATE {
                    portset.protocol = Protocol_get(Protocol_RDATE);
                  }
                | PROTOCOL REDIS  {
                    portset.protocol = Protocol_get(Protocol_REDIS);
                  }
                | PROTOCOL RSYNC {
                    portset.protocol = Protocol_get(Protocol_RSYNC);
                  }
                | PROTOCOL TNS {
                    portset.protocol = Protocol_get(Protocol_TNS);
                  }
                | PROTOCOL PGSQL {
                    portset.protocol = Protocol_get(Protocol_PGSQL);
                  }
                | PROTOCOL LMTP {
                    portset.protocol = Protocol_get(Protocol_LMTP);
                  }
                | PROTOCOL GPS {
                    portset.protocol = Protocol_get(Protocol_GPS);
                  }
                | PROTOCOL RADIUS secret {
                    portset.protocol = Protocol_get(Protocol_RADIUS);
                  }
                | PROTOCOL MEMCACHE {
                    portset.protocol = Protocol_get(Protocol_MEMCACHE);
                  }
                | PROTOCOL WEBSOCKET websocketlist {
                    portset.protocol = Protocol_get(Protocol_WEBSOCKET);
                  }
                | sendexpectlist {
                    portset.protocol = Protocol_get(Protocol_GENERIC);
                  }
                ;

sendexpectlist  : sendexpect
                | sendexpectlist sendexpect
                ;

sendexpect      : SEND STRING {
                    addgeneric(&portset, $2, NULL);
                  }
                | EXPECT STRING {
                    addgeneric(&portset, NULL, $2);
                  }
                ;

websocketlist   : websocket
                | websocketlist websocket
                ;

websocket       : ORIGIN STRING {
                    portset.pathname = $2;
                  }
                | REQUEST PATH {
                    portset.request = $2;
                  }
                | HOST STRING {
                    portset.request_hostheader = $2;
                  }
                | VERSIONOPT NUMBER {
                    portset.version = $<number>2;
                  }
                ;

target          : /* EMPTY */
                | TARGET MAILADDR {
                    portset.request = $2;
                  }
                | TARGET STRING {
                    portset.request = $2;
                  }
                ;

maxforward      : /* EMPTY */
                |  MAXFORWARD NUMBER {
                     portset.maxforward = verifyMaxForward($2);
                   }
                ;

httplist        : /* EMPTY */
                | httplist http
                ;

http            : request
                | responsesum
                | status
                | hostheader
                | '[' httpheaderlist ']'
                ;

status          : STATUS operator NUMBER {
                    portset.operator = $<number>2;
                    portset.status = $<number>3;
                  }
                ;

request         : REQUEST PATH {
                    portset.request = Util_urlEncode($2);
                    FREE($2);
                  }
                ;

responsesum     : CHECKSUM STRING {
                    portset.request_checksum = $2;
                  }
                ;

hostheader      : HOSTHEADER STRING {
                    portset.request_hostheader = $2;
                  }
                ;

httpheaderlist  : /* EMPTY */
                | httpheaderlist HTTPHEADER {
                        if (! portset.http_headers) {
                                portset.http_headers = List_new();
                        }
                        List_append(portset.http_headers, $2);
                 }
                ;

secret          : SECRET STRING {
                    portset.request = $2;
                  }
                ;

apache_stat_list: apache_stat
                | apache_stat_list OR apache_stat
                ;

apache_stat     : LOGLIMIT operator NUMBER PERCENT {
                    portset.ApacheStatus.loglimitOP = $<number>2;
                    portset.ApacheStatus.loglimit = $<number>3;
                  }
                | CLOSELIMIT operator NUMBER PERCENT {
                    portset.ApacheStatus.closelimitOP = $<number>2;
                    portset.ApacheStatus.closelimit = $<number>3;
                  }
                | DNSLIMIT operator NUMBER PERCENT {
                    portset.ApacheStatus.dnslimitOP = $<number>2;
                    portset.ApacheStatus.dnslimit = $<number>3;
                  }
                | KEEPALIVELIMIT operator NUMBER PERCENT {
                    portset.ApacheStatus.keepalivelimitOP = $<number>2;
                    portset.ApacheStatus.keepalivelimit = $<number>3;
                  }
                | REPLYLIMIT operator NUMBER PERCENT {
                    portset.ApacheStatus.replylimitOP = $<number>2;
                    portset.ApacheStatus.replylimit = $<number>3;
                  }
                | REQUESTLIMIT operator NUMBER PERCENT {
                    portset.ApacheStatus.requestlimitOP = $<number>2;
                    portset.ApacheStatus.requestlimit = $<number>3;
                  }
                | STARTLIMIT operator NUMBER PERCENT {
                    portset.ApacheStatus.startlimitOP = $<number>2;
                    portset.ApacheStatus.startlimit = $<number>3;
                  }
                | WAITLIMIT operator NUMBER PERCENT {
                    portset.ApacheStatus.waitlimitOP = $<number>2;
                    portset.ApacheStatus.waitlimit = $<number>3;
                  }
                | GRACEFULLIMIT operator NUMBER PERCENT {
                    portset.ApacheStatus.gracefullimitOP = $<number>2;
                    portset.ApacheStatus.gracefullimit = $<number>3;
                  }
                | CLEANUPLIMIT operator NUMBER PERCENT {
                    portset.ApacheStatus.cleanuplimitOP = $<number>2;
                    portset.ApacheStatus.cleanuplimit = $<number>3;
                  }
                ;

exist           : IF NOT EXIST rate1 THEN action1 recovery {
                    addeventaction(&(nonexistset).action, $<number>6, $<number>7);
                    addnonexist(&nonexistset);
                  }
                ;


pid             : IF CHANGED PID rate1 THEN action1 {
                    addeventaction(&(pidset).action, $<number>6, Action_Ignored);
                    addpid(&pidset);
                  }
                ;

ppid            : IF CHANGED PPID rate1 THEN action1 {
                    addeventaction(&(ppidset).action, $<number>6, Action_Ignored);
                    addppid(&ppidset);
                  }
                ;

uptime          : IF UPTIME operator NUMBER time rate1 THEN action1 recovery {
                    uptimeset.operator = $<number>3;
                    uptimeset.uptime = ((unsigned long long)$4 * $<number>5);
                    addeventaction(&(uptimeset).action, $<number>8, $<number>9);
                    adduptime(&uptimeset);
                  }

icmpcount       : /* EMPTY */ {
                   $<number>$ = ICMP_ATTEMPT_COUNT;
                  }
                | COUNT NUMBER {
                        $<number>$ = $2;
                 }
                ;

exectimeout     : /* EMPTY */ {
                   $<number>$ = EXEC_TIMEOUT;
                  }
                | TIMEOUT NUMBER SECOND {
                   $<number>$ = $2;
                  }
                ;

programtimeout  : /* EMPTY */ {
                   $<number>$ = PROGRAM_TIMEOUT; // Default program status check timeout is 5 min
                  }
                | TIMEOUT NUMBER SECOND {
                   $<number>$ = $2;
                  }
                ;

nettimeout      : /* EMPTY */ {
                   $<number>$ = NET_TIMEOUT; // timeout is in milliseconds
                  }
                | TIMEOUT NUMBER SECOND {
                   $<number>$ = $2 * 1000; // net timeout is in milliseconds internally
                  }
                ;

retry           : /* EMPTY */ {
                   $<number>$ = 1;
                  }
                | RETRY NUMBER {
                   $<number>$ = $2;
                  }
                ;

actionrate      : IF NUMBER RESTART NUMBER CYCLE THEN action1 {
                   actionrateset.count = $2;
                   actionrateset.cycle = $4;
                   addeventaction(&(actionrateset).action, $<number>7, Action_Alert);
                   addactionrate(&actionrateset);
                 }
                | IF NUMBER RESTART NUMBER CYCLE THEN TIMEOUT {
                   actionrateset.count = $2;
                   actionrateset.cycle = $4;
                   addeventaction(&(actionrateset).action, Action_Unmonitor, Action_Alert);
                   addactionrate(&actionrateset);
                 }
                ;

urloption       : /* EMPTY */
                | CONTENT urloperator STRING {
                    seturlrequest($<number>2, $<string>3);
                    FREE($3);
                  }
                ;

urloperator     : EQUAL    { $<number>$ = Operator_Equal; }
                | NOTEQUAL { $<number>$ = Operator_NotEqual; }
                ;

alert           : alertmail formatlist reminder {
                   mailset.events = Event_All;
                   addmail($<string>1, &mailset, &current->maillist);
                  }
                | alertmail '{' eventoptionlist '}' formatlist reminder {
                   addmail($<string>1, &mailset, &current->maillist);
                  }
                | alertmail NOT '{' eventoptionlist '}' formatlist reminder {
                   mailset.events = ~mailset.events;
                   addmail($<string>1, &mailset, &current->maillist);
                  }
                | noalertmail {
                   addmail($<string>1, &mailset, &current->maillist);
                  }
                ;

alertmail       : ALERT MAILADDR { $<string>$ = $2; }
                ;

noalertmail     : NOALERT MAILADDR { $<string>$ = $2; }
                ;

eventoptionlist : eventoption
                | eventoptionlist eventoption
                ;

eventoption     : ACTION          { mailset.events |= Event_Action; }
                | BYTEIN          { mailset.events |= Event_ByteIn; }
                | BYTEOUT         { mailset.events |= Event_ByteOut; }
                | CHECKSUM        { mailset.events |= Event_Checksum; }
                | CONNECTION      { mailset.events |= Event_Connection; }
                | CONTENT         { mailset.events |= Event_Content; }
                | DATA            { mailset.events |= Event_Data; }
                | EXEC            { mailset.events |= Event_Exec; }
                | FSFLAG          { mailset.events |= Event_Fsflag; }
                | GID             { mailset.events |= Event_Gid; }
                | ICMP            { mailset.events |= Event_Icmp; }
                | INSTANCE        { mailset.events |= Event_Instance; }
                | INVALID         { mailset.events |= Event_Invalid; }
                | LINK            { mailset.events |= Event_Link; }
                | NONEXIST        { mailset.events |= Event_Nonexist; }
                | PACKETIN        { mailset.events |= Event_PacketIn; }
                | PACKETOUT       { mailset.events |= Event_PacketOut; }
                | PERMISSION      { mailset.events |= Event_Permission; }
                | PID             { mailset.events |= Event_Pid; }
                | PPID            { mailset.events |= Event_PPid; }
                | RESOURCE        { mailset.events |= Event_Resource; }
                | SATURATION      { mailset.events |= Event_Saturation; }
                | SIZE            { mailset.events |= Event_Size; }
                | SPEED           { mailset.events |= Event_Speed; }
                | STATUS          { mailset.events |= Event_Status; }
                | TIMEOUT         { mailset.events |= Event_Timeout; }
                | TIMESTAMP       { mailset.events |= Event_Timestamp; }
                | UID             { mailset.events |= Event_Uid; }
                | UPTIME          { mailset.events |= Event_Uptime; }
                ;

formatlist      : /* EMPTY */
                | MAILFORMAT '{' formatoptionlist '}'
                ;

formatoptionlist: formatoption
                | formatoptionlist formatoption
                ;

formatoption    : MAILFROM { mailset.from = $1; }
                | MAILREPLYTO { mailset.replyto = $1; }
                | MAILSUBJECT { mailset.subject = $1; }
                | MAILBODY { mailset.message = $1; }
                ;

every           : EVERY NUMBER CYCLE {
                   current->every.type = Every_SkipCycles;
                   current->every.spec.cycle.number = $2;
                 }
                | EVERY TIMESPEC {
                   current->every.type = Every_Cron;
                   current->every.spec.cron = $2;
                 }
                | NOTEVERY TIMESPEC {
                   current->every.type = Every_NotInCron;
                   current->every.spec.cron = $2;
                 }
                ;

mode            : MODE ACTIVE  {
                    current->mode = Monitor_Active;
                  }
                | MODE PASSIVE {
                    current->mode = Monitor_Passive;
                  }
                | MODE MANUAL  {
                    current->mode = Monitor_Manual;
                    current->monitor = Monitor_Not;
                  }
                ;

group           : GROUP STRINGNAME { addservicegroup($2); FREE($2);}
                ;


depend          : DEPENDS dependlist
                ;

dependlist      : dependant
                | dependlist dependant
                ;

dependant       : SERVICENAME { adddependant($<string>1); }
                ;

statusvalue     : IF STATUS operator NUMBER rate1 THEN action1 recovery {
                        statusset.initialized = true;
                        statusset.operator = $<number>3;
                        statusset.return_value = $<number>4;
                        addeventaction(&(statusset).action, $<number>7, $<number>8);
                        addstatus(&statusset);
                   }
                | IF CHANGED STATUS rate1 THEN action1 {
                        statusset.initialized = false;
                        statusset.operator = Operator_Changed;
                        statusset.return_value = 0;
                        addeventaction(&(statusset).action, $<number>6, Action_Ignored);
                        addstatus(&statusset);
                   }
                ;

resourceprocess : IF resourceprocesslist rate1 THEN action1 recovery {
                     addeventaction(&(resourceset).action, $<number>5, $<number>6);
                     addresource(&resourceset);
                   }
                ;

resourceprocesslist : resourceprocessopt
                    | resourceprocesslist resourceprocessopt
                    ;

resourceprocessopt  : resourcecpuproc
                    | resourcemem
                    | resourcechild
                    | resourceload
                    ;

resourcesystem  : IF resourcesystemlist rate1 THEN action1 recovery {
                     addeventaction(&(resourceset).action, $<number>5, $<number>6);
                     addresource(&resourceset);
                   }
                ;

resourcesystemlist : resourcesystemopt
                   | resourcesystemlist resourcesystemopt
                   ;

resourcesystemopt  : resourceload
                   | resourcemem
                   | resourceswap
                   | resourcecpu
                   ;

resourcecpuproc : CPU operator NUMBER PERCENT {
                    resourceset.resource_id = Resource_CpuPercent;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10);
                  }
                | TOTALCPU operator NUMBER PERCENT {
                    resourceset.resource_id = Resource_CpuPercentTotal;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10);
                  }
                ;

resourcecpu     : resourcecpuid operator NUMBER PERCENT {
                    resourceset.resource_id = $<number>1;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10);
                  }
                ;

resourcecpuid   : CPUUSER   { $<number>$ = Resource_CpuUser; }
                | CPUSYSTEM { $<number>$ = Resource_CpuSystem; }
                | CPUWAIT   { $<number>$ = Resource_CpuWait; }
                ;

resourcemem     : MEMORY operator value unit {
                    resourceset.resource_id = Resource_MemoryKbyte;
                    resourceset.operator = $<number>2;
                    resourceset.limit = (int) ($<real>3 * ($<number>4 / 1024.0));
                  }
                | MEMORY operator NUMBER PERCENT {
                    resourceset.resource_id = Resource_MemoryPercent;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10);
                  }
                | TOTALMEMORY operator value unit {
                    resourceset.resource_id = Resource_MemoryKbyteTotal;
                    resourceset.operator = $<number>2;
                    resourceset.limit = (int) ($<real>3 * ($<number>4 / 1024.0));
                  }
                | TOTALMEMORY operator NUMBER PERCENT  {
                    resourceset.resource_id = Resource_MemoryPercentTotal;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10);
                  }
                ;

resourceswap    : SWAP operator value unit {
                    resourceset.resource_id = Resource_SwapKbyte;
                    resourceset.operator = $<number>2;
                    resourceset.limit = (int) ($<real>3 * ($<number>4 / 1024.0));
                  }
                | SWAP operator NUMBER PERCENT {
                    resourceset.resource_id = Resource_SwapPercent;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10);
                  }
                ;

resourcechild   : CHILDREN operator NUMBER {
                    resourceset.resource_id = Resource_Children;
                    resourceset.operator = $<number>2;
                    resourceset.limit = (int) $3;
                  }
                ;

resourceload    : resourceloadavg operator value {
                    resourceset.resource_id = $<number>1;
                    resourceset.operator = $<number>2;
                    resourceset.limit = (int) ($<real>3 * 10.0);
                  }
                ;

resourceloadavg : LOADAVG1  { $<number>$ = Resource_LoadAverage1m; }
                | LOADAVG5  { $<number>$ = Resource_LoadAverage5m; }
                | LOADAVG15 { $<number>$ = Resource_LoadAverage15m; }
                ;

value           : REAL { $<real>$ = $1; }
                | NUMBER { $<real>$ = (float) $1; }
                ;

timestamp       : IF TIMESTAMP operator NUMBER time rate1 THEN action1 recovery {
                    timestampset.operator = $<number>3;
                    timestampset.time = ($4 * $<number>5);
                    addeventaction(&(timestampset).action, $<number>8, $<number>9);
                    addtimestamp(&timestampset, false);
                  }
                | IF CHANGED TIMESTAMP rate1 THEN action1 {
                    timestampset.test_changes = true;
                    addeventaction(&(timestampset).action, $<number>6, Action_Ignored);
                    addtimestamp(&timestampset, true);
                  }
                ;

operator        : /* EMPTY */ { $<number>$ = Operator_Equal; }
                | GREATER     { $<number>$ = Operator_Greater; }
                | LESS        { $<number>$ = Operator_Less; }
                | EQUAL       { $<number>$ = Operator_Equal; }
                | NOTEQUAL    { $<number>$ = Operator_NotEqual; }
                | CHANGED     { $<number>$ = Operator_Changed; }
                ;

time            : /* EMPTY */ { $<number>$ = Time_Second; }
                | SECOND      { $<number>$ = Time_Second; }
                | MINUTE      { $<number>$ = Time_Minute; }
                | HOUR        { $<number>$ = Time_Hour; }
                | DAY         { $<number>$ = Time_Day; }
                | MONTH       { $<number>$ = Time_Month; }
                ;

totaltime       : MINUTE      { $<number>$ = Time_Minute; }
                | HOUR        { $<number>$ = Time_Hour; }
                | DAY         { $<number>$ = Time_Day; }

currenttime     : /* EMPTY */ { $<number>$ = Time_Second; }
                | SECOND      { $<number>$ = Time_Second; }

action          : ALERT                            { $<number>$ = Action_Alert; }
                | EXEC argumentlist                { $<number>$ = Action_Exec; }
                | EXEC argumentlist useroptionlist { $<number>$ = Action_Exec; }
                | RESTART                          { $<number>$ = Action_Restart; }
                | START                            { $<number>$ = Action_Start; }
                | STOP                             { $<number>$ = Action_Stop; }
                | UNMONITOR                        { $<number>$ = Action_Unmonitor; }
                ;

action1         : action {
                    $<number>$ = $<number>1;
                    if ($<number>1 == Action_Exec && command) {
                      command1 = command;
                      command = NULL;
                    }
                  }
                ;

action2         : action {
                    $<number>$ = $<number>1;
                    if ($<number>1 == Action_Exec && command) {
                      command2 = command;
                      command = NULL;
                    }
                  }
                ;

rate1           : /* EMPTY */
                | NUMBER CYCLE {
                    rate1.count  = $<number>1;
                    rate1.cycles = $<number>1;
                    if (rate1.cycles < 1 || rate1.cycles > BITMAP_MAX)
                      yyerror2("The number of cycles must be between 1 and %d", BITMAP_MAX);
                  }
                | NUMBER NUMBER CYCLE {
                    rate1.count  = $<number>1;
                    rate1.cycles = $<number>2;
                    if (rate1.cycles < 1 || rate1.cycles > BITMAP_MAX)
                      yyerror2("The number of cycles must be between 1 and %d", BITMAP_MAX);
                    if (rate1.count < 1 || rate1.count > rate1.cycles)
                      yyerror2("The number of events must be bigger then 0 and less than poll cycles");
                  }
                ;

rate2           : /* EMPTY */
                | NUMBER CYCLE {
                    rate2.count  = $<number>1;
                    rate2.cycles = $<number>1;
                    if (rate2.cycles < 1 || rate2.cycles > BITMAP_MAX)
                      yyerror2("The number of cycles must be between 1 and %d", BITMAP_MAX);
                  }
                | NUMBER NUMBER CYCLE {
                    rate2.count  = $<number>1;
                    rate2.cycles = $<number>2;
                    if (rate2.cycles < 1 || rate2.cycles > BITMAP_MAX)
                      yyerror2("The number of cycles must be between 1 and %d", BITMAP_MAX);
                    if (rate2.count < 1 || rate2.count > rate2.cycles)
                      yyerror2("The number of events must be bigger then 0 and less than poll cycles");
                  }
                ;

recovery        : /* EMPTY */ {
                    $<number>$ = Action_Alert;
                  }
                | ELSE IF RECOVERED rate2 THEN action2 {
                    $<number>$ = $<number>6;
                  }
                | ELSE IF PASSED rate2 THEN action2 {
                    $<number>$ = $<number>6;
                  }
                | ELSE IF SUCCEEDED rate2 THEN action2 {
                    $<number>$ = $<number>6;
                  }
                ;

checksum        : IF FAILED hashtype CHECKSUM rate1 THEN action1 recovery {
                    addeventaction(&(checksumset).action, $<number>7, $<number>8);
                    addchecksum(&checksumset);
                  }
                | IF FAILED hashtype CHECKSUM EXPECT STRING rate1 THEN action1
                  recovery {
                    snprintf(checksumset.hash, sizeof(checksumset.hash), "%s", $6);
                    FREE($6);
                    addeventaction(&(checksumset).action, $<number>9, $<number>10);
                    addchecksum(&checksumset);
                  }
                | IF CHANGED hashtype CHECKSUM rate1 THEN action1 {
                    checksumset.test_changes = true;
                    addeventaction(&(checksumset).action, $<number>7, Action_Ignored);
                    addchecksum(&checksumset);
                  }
                ;
hashtype        : /* EMPTY */ { checksumset.type = Hash_Unknown; }
                | MD5HASH     { checksumset.type = Hash_Md5; }
                | SHA1HASH    { checksumset.type = Hash_Sha1; }
                ;

inode           : IF INODE operator NUMBER rate1 THEN action1 recovery {
                    filesystemset.resource = Resource_Inode;
                    filesystemset.operator = $<number>3;
                    filesystemset.limit_absolute = $4;
                    addeventaction(&(filesystemset).action, $<number>7, $<number>8);
                    addfilesystem(&filesystemset);
                  }
                | IF INODE operator NUMBER PERCENT rate1 THEN action1 recovery {
                    filesystemset.resource = Resource_Inode;
                    filesystemset.operator = $<number>3;
                    filesystemset.limit_percent = (int)($4 * 10);
                    addeventaction(&(filesystemset).action, $<number>8, $<number>9);
                    addfilesystem(&filesystemset);
                  }
                ;

space           : IF SPACE operator value unit rate1 THEN action1 recovery {
                    if (! filesystem_usage(current))
                      yyerror2("Cannot read usage of filesystem %s", current->path);
                    filesystemset.resource = Resource_Space;
                    filesystemset.operator = $<number>3;
                    filesystemset.limit_absolute = (long long)((double)$<real>4 / (double)current->inf->priv.filesystem.f_bsize * (double)$<number>5);
                    addeventaction(&(filesystemset).action, $<number>8, $<number>9);
                    addfilesystem(&filesystemset);
                  }
                | IF SPACE operator NUMBER PERCENT rate1 THEN action1 recovery {
                    filesystemset.resource = Resource_Space;
                    filesystemset.operator = $<number>3;
                    filesystemset.limit_percent = (int)($4 * 10);
                    addeventaction(&(filesystemset).action, $<number>8, $<number>9);
                    addfilesystem(&filesystemset);
                  }
                ;

fsflag          : IF CHANGED FSFLAG rate1 THEN action1 {
                    addeventaction(&(fsflagset).action, $<number>6, Action_Ignored);
                    addfsflag(&fsflagset);
                  }
                ;

unit            : /* empty */  { $<number>$ = Unit_Byte; }
                | BYTE         { $<number>$ = Unit_Byte; }
                | KILOBYTE     { $<number>$ = Unit_Kilobyte; }
                | MEGABYTE     { $<number>$ = Unit_Megabyte; }
                | GIGABYTE     { $<number>$ = Unit_Gigabyte; }
                ;

permission      : IF FAILED PERMISSION NUMBER rate1 THEN action1 recovery {
                    permset.perm = check_perm($4);
                    addeventaction(&(permset).action, $<number>7, $<number>8);
                    addperm(&permset);
                  }
                | IF CHANGED PERMISSION rate1 THEN action1 recovery {
                    permset.test_changes = true;
                    addeventaction(&(permset).action, $<number>6, Action_Ignored);
                    addperm(&permset);
                  }
                ;

match           : IF matchflagnot MATCH PATH rate1 THEN action1 {
                    matchset.ignore = false;
                    matchset.match_path = $4;
                    matchset.match_string = NULL;
                    addmatchpath(&matchset, $<number>7);
                    FREE($4);
                  }
                | IF matchflagnot MATCH STRING rate1 THEN action1 {
                    matchset.ignore = false;
                    matchset.match_path = NULL;
                    matchset.match_string = $4;
                    addmatch(&matchset, $<number>7, 0);
                  }
                | IGNORE matchflagnot MATCH PATH {
                    matchset.ignore = true;
                    matchset.match_path = $4;
                    matchset.match_string = NULL;
                    addmatchpath(&matchset, Action_Ignored);
                    FREE($4);
                  }
                | IGNORE matchflagnot MATCH STRING {
                    matchset.ignore = true;
                    matchset.match_path = NULL;
                    matchset.match_string = $4;
                    addmatch(&matchset, Action_Ignored, 0);
                  }
                ;

matchflagnot    : /* EMPTY */ {
                    matchset.not = false;
                  }
                | NOT {
                    matchset.not = true;
                  }
                ;


size            : IF SIZE operator NUMBER unit rate1 THEN action1 recovery {
                    sizeset.operator = $<number>3;
                    sizeset.size = ((unsigned long long)$4 * $<number>5);
                    addeventaction(&(sizeset).action, $<number>8, $<number>9);
                    addsize(&sizeset);
                  }
                | IF CHANGED SIZE rate1 THEN action1 {
                    sizeset.test_changes = true;
                    addeventaction(&(sizeset).action, $<number>6, Action_Ignored);
                    addsize(&sizeset);
                  }
                ;

uid             : IF FAILED UID STRING rate1 THEN action1 recovery {
                    uidset.uid = get_uid($4, 0);
                    addeventaction(&(uidset).action, $<number>7, $<number>8);
                    current->uid = adduid(&uidset);
                    FREE($4);
                  }
                | IF FAILED UID NUMBER rate1 THEN action1 recovery {
                    uidset.uid = get_uid(NULL, $4);
                    addeventaction(&(uidset).action, $<number>7, $<number>8);
                    current->uid = adduid(&uidset);
                  }
                ;

euid            : IF FAILED EUID STRING rate1 THEN action1 recovery {
                    uidset.uid = get_uid($4, 0);
                    addeventaction(&(uidset).action, $<number>7, $<number>8);
                    current->euid = adduid(&uidset);
                    FREE($4);
                  }
                | IF FAILED EUID NUMBER rate1 THEN action1 recovery {
                    uidset.uid = get_uid(NULL, $4);
                    addeventaction(&(uidset).action, $<number>7, $<number>8);
                    current->euid = adduid(&uidset);
                  }
                ;

gid             : IF FAILED GID STRING rate1 THEN action1 recovery {
                    gidset.gid = get_gid($4, 0);
                    addeventaction(&(gidset).action, $<number>7, $<number>8);
                    current->gid = addgid(&gidset);
                    FREE($4);
                  }
                | IF FAILED GID NUMBER rate1 THEN action1 recovery {
                    gidset.gid = get_gid(NULL, $4);
                    addeventaction(&(gidset).action, $<number>7, $<number>8);
                    current->gid = addgid(&gidset);
                  }
                ;

linkstatus   : IF FAILED LINK rate1 THEN action1 recovery {
                    addeventaction(&(linkstatusset).action, $<number>6, $<number>7);
                    addlinkstatus(current, &linkstatusset);
                  }
                ;

linkspeed    : IF CHANGED LINK rate1 THEN action1 recovery {
                    addeventaction(&(linkspeedset).action, $<number>6, $<number>7);
                    addlinkspeed(current, &linkspeedset);
                  }

linksaturation : IF SATURATION operator NUMBER PERCENT rate1 THEN action1 recovery {
                    linksaturationset.operator = $<number>3;
                    linksaturationset.limit = (unsigned long long)$4;
                    addeventaction(&(linksaturationset).action, $<number>8, $<number>9);
                    addlinksaturation(current, &linksaturationset);
                  }
                ;

upload          : IF UPLOAD operator NUMBER unit currenttime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>3;
                    bandwidthset.limit = ((unsigned long long)$4 * $<number>5);
                    bandwidthset.rangecount = 1;
                    bandwidthset.range = $<number>6;
                    addeventaction(&(bandwidthset).action, $<number>9, $<number>10);
                    addbandwidth(&(current->uploadbyteslist), &bandwidthset);
                  }
                | IF TOTAL UPLOAD operator NUMBER unit totaltime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>4;
                    bandwidthset.limit = ((unsigned long long)$5 * $<number>6);
                    bandwidthset.rangecount = 1;
                    bandwidthset.range = $<number>7;
                    addeventaction(&(bandwidthset).action, $<number>10, $<number>11);
                    addbandwidth(&(current->uploadbyteslist), &bandwidthset);
                  }
                | IF TOTAL UPLOAD operator NUMBER unit NUMBER totaltime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>4;
                    bandwidthset.limit = ((unsigned long long)$5 * $<number>6);
                    bandwidthset.rangecount = $7;
                    bandwidthset.range = $<number>8;
                    addeventaction(&(bandwidthset).action, $<number>11, $<number>12);
                    addbandwidth(&(current->uploadbyteslist), &bandwidthset);
                  }
                | IF UPLOAD operator NUMBER PACKET currenttime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>3;
                    bandwidthset.limit = (unsigned long long)$4;
                    bandwidthset.rangecount = 1;
                    bandwidthset.range = $<number>6;
                    addeventaction(&(bandwidthset).action, $<number>9, $<number>10);
                    addbandwidth(&(current->uploadpacketslist), &bandwidthset);
                  }
                | IF TOTAL UPLOAD operator NUMBER PACKET totaltime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>4;
                    bandwidthset.limit = (unsigned long long)$5;
                    bandwidthset.rangecount = 1;
                    bandwidthset.range = $<number>7;
                    addeventaction(&(bandwidthset).action, $<number>10, $<number>11);
                    addbandwidth(&(current->uploadpacketslist), &bandwidthset);
                  }
                | IF TOTAL UPLOAD operator NUMBER PACKET NUMBER totaltime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>4;
                    bandwidthset.limit = (unsigned long long)$5;
                    bandwidthset.rangecount = $7;
                    bandwidthset.range = $<number>8;
                    addeventaction(&(bandwidthset).action, $<number>11, $<number>12);
                    addbandwidth(&(current->uploadpacketslist), &bandwidthset);
                  }
                ;

download        : IF DOWNLOAD operator NUMBER unit currenttime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>3;
                    bandwidthset.limit = ((unsigned long long)$4 * $<number>5);
                    bandwidthset.rangecount = 1;
                    bandwidthset.range = $<number>6;
                    addeventaction(&(bandwidthset).action, $<number>9, $<number>10);
                    addbandwidth(&(current->downloadbyteslist), &bandwidthset);
                  }
                | IF TOTAL DOWNLOAD operator NUMBER unit totaltime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>4;
                    bandwidthset.limit = ((unsigned long long)$5 * $<number>6);
                    bandwidthset.rangecount = 1;
                    bandwidthset.range = $<number>7;
                    addeventaction(&(bandwidthset).action, $<number>10, $<number>11);
                    addbandwidth(&(current->downloadbyteslist), &bandwidthset);
                  }
                | IF TOTAL DOWNLOAD operator NUMBER unit NUMBER totaltime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>4;
                    bandwidthset.limit = ((unsigned long long)$5 * $<number>6);
                    bandwidthset.rangecount = $7;
                    bandwidthset.range = $<number>8;
                    addeventaction(&(bandwidthset).action, $<number>11, $<number>12);
                    addbandwidth(&(current->downloadbyteslist), &bandwidthset);
                  }
                | IF DOWNLOAD operator NUMBER PACKET currenttime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>3;
                    bandwidthset.limit = (unsigned long long)$4;
                    bandwidthset.rangecount = 1;
                    bandwidthset.range = $<number>6;
                    addeventaction(&(bandwidthset).action, $<number>9, $<number>10);
                    addbandwidth(&(current->downloadpacketslist), &bandwidthset);
                  }
                | IF TOTAL DOWNLOAD operator NUMBER PACKET totaltime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>4;
                    bandwidthset.limit = (unsigned long long)$5;
                    bandwidthset.rangecount = 1;
                    bandwidthset.range = $<number>7;
                    addeventaction(&(bandwidthset).action, $<number>10, $<number>11);
                    addbandwidth(&(current->downloadpacketslist), &bandwidthset);
                  }
                | IF TOTAL DOWNLOAD operator NUMBER PACKET NUMBER totaltime rate1 THEN action1 recovery {
                    bandwidthset.operator = $<number>4;
                    bandwidthset.limit = (unsigned long long)$5;
                    bandwidthset.rangecount = $7;
                    bandwidthset.range = $<number>8;
                    addeventaction(&(bandwidthset).action, $<number>11, $<number>12);
                    addbandwidth(&(current->downloadpacketslist), &bandwidthset);
                  }
                ;

icmptype        : TYPE ICMPECHO { $<number>$ = ICMP_ECHO; }
                ;

reminder        : /* EMPTY */           { mailset.reminder = 0; }
                | REMINDER NUMBER       { mailset.reminder = $<number>2; }
                | REMINDER NUMBER CYCLE { mailset.reminder = $<number>2; }
                ;

%%


/* -------------------------------------------------------- Parser interface */


/**
 * Syntactic error routine
 *
 * This routine is automatically called by the lexer!
 */
void yyerror(const char *s, ...) {
        va_list ap;
        char *msg = NULL;

        ASSERT(s);

        va_start(ap,s);
        msg = Str_vcat(s, ap);
        va_end(ap);

        LogError("%s:%i: %s '%s'\n", currentfile, lineno, msg, yytext);
        cfg_errflag++;

        FREE(msg);

}

/**
 * Syntactical warning routine
 */
void yywarning(const char *s, ...) {
        va_list ap;
        char *msg = NULL;

        ASSERT(s);

        va_start(ap,s);
        msg = Str_vcat(s, ap);
        va_end(ap);

        LogWarning("%s:%i: %s '%s'\n", currentfile, lineno, msg, yytext);

        FREE(msg);

}

/**
 * Argument error routine
 */
void yyerror2(const char *s, ...) {
        va_list ap;
        char *msg = NULL;

        ASSERT(s);

        va_start(ap,s);
        msg = Str_vcat(s, ap);
        va_end(ap);

        LogError("%s:%i: %s '%s'\n", argcurrentfile, arglineno, msg, argyytext);
        cfg_errflag++;

        FREE(msg);

}

/**
 * Argument warning routine
 */
void yywarning2(const char *s, ...) {
        va_list ap;
        char *msg = NULL;

        ASSERT(s);

        va_start(ap,s);
        msg = Str_vcat(s, ap);
        va_end(ap);

        LogWarning("%s:%i: %s '%s'\n", argcurrentfile, arglineno, msg, argyytext);

        FREE(msg);

}

/*
 * The Parser hook - start parsing the control file
 * Returns true if parsing succeeded, otherwise false
 */
boolean_t parse(char *controlfile) {

        ASSERT(controlfile);

        servicelist = tail = current = NULL;

        if ((yyin = fopen(controlfile,"r")) == (FILE *)NULL) {
                LogError("Cannot open the control file '%s' -- %s\n", controlfile, STRERROR);
                return false;
        }

        currentfile = Str_dup(controlfile);

        /*
         * Creation of the global service list is synchronized
         */
        LOCK(Run.mutex)
        {
                preparse();
                yyparse();
                fclose(yyin);
                postparse();
        }
        END_LOCK;

        FREE(currentfile);

        if (argyytext != NULL)
                FREE(argyytext);

        /*
         * Secure check the monitrc file. The run control file must have the
         * same uid as the REAL uid of this process, it must have permissions
         * no greater than 700 and it must not be a symbolic link.
         */
        if (! file_checkStat(controlfile, "control file", S_IRUSR|S_IWUSR|S_IXUSR))
                return false;

        return cfg_errflag == 0;
}


/* ----------------------------------------------------------------- Private */


/**
 * Initialize objects used by the parser.
 */
static void preparse() {
        int i;

        /* Set instance incarnation ID */
        time(&Run.incarnation);
        /* Reset lexer */
        buffer_stack_ptr            = 0;
        lineno                      = 1;
        arglineno                   = 1;
        argcurrentfile              = NULL;
        argyytext                   = NULL;
        /* Reset parser */
        Run.stopped                 = false;
        Run.dolog                   = false;
        Run.doaction                = false;
        Run.dommonitcredentials     = true;
        Run.mmonitcredentials       = NULL;
        Run.httpd.flags             = Httpd_Disabled | Httpd_Signature;
        Run.httpd.credentials       = NULL;
        memset(&(Run.httpd.socket), 0, sizeof(Run.httpd.socket));
        Run.mailserver_timeout      = SMTP_TIMEOUT;
        Run.eventlist               = NULL;
        Run.eventlist_dir           = NULL;
        Run.eventlist_slots         = -1;
        Run.system                  = NULL;
        Run.expectbuffer            = STRLEN;
        Run.mmonits                 = NULL;
        Run.maillist                = NULL;
        Run.mailservers             = NULL;
        Run.MailFormat.from         = NULL;
        Run.MailFormat.replyto      = NULL;
        Run.MailFormat.subject      = NULL;
        Run.MailFormat.message      = NULL;
        depend_list                 = NULL;
        Run.handler_init            = true;
        Run.fipsEnabled             = false;
        for (i = 0; i <= Handler_Max; i++)
                Run.handler_queue[i] = 0;
        /*
         * Initialize objects
         */
        reset_uidset();
        reset_gidset();
        reset_statusset();
        reset_sizeset();
        reset_mailset();
        reset_mailserverset();
        reset_portset();
        reset_permset();
        reset_icmpset();
        reset_linkstatusset();
        reset_linkspeedset();
        reset_linksaturationset();
        reset_bandwidthset();
        reset_rateset();
        reset_filesystemset();
        reset_resourceset();
        reset_checksumset();
        reset_timestampset();
        reset_actionrateset();
}


/*
 * Check that values are reasonable after parsing
 */
static void postparse() {
        if (cfg_errflag)
                return;

        /* If defined - add the last service to the service list */
        if (current)
                addservice(current);

        /* Check that we do not start monit in daemon mode without having a poll time */
        if (! Run.polltime && (Run.isdaemon || Run.init)) {
                LogError("Poll time is invalid or not defined. Please define poll time in the control file\nas a number (> 0)  or use the -d option when starting monit\n");
                cfg_errflag++;
        }

        if (Run.logfile)
                Run.dolog = true;

        /* Add the default general system service if not specified explicitly: service name default to hostname */
        if (! Run.system) {
                char hostname[STRLEN];
                if (Util_getfqdnhostname(hostname, sizeof(hostname))) {
                        LogError("Cannot get system hostname -- please add 'check system <name>'\n");
                        cfg_errflag++;
                }
                if (Util_existService(hostname)) {
                        LogError("'check system' not defined in control file, failed to add automatic configuration (service name %s is used already) -- please add 'check system <name>' manually\n", hostname);
                        cfg_errflag++;
                } else {
                        Run.system = createservice(Service_System, Str_dup(hostname), Str_dup(""), check_system);
                        addservice(Run.system);
                }
        }

        if (Run.mmonits) {
                if (Run.httpd.flags & Httpd_Net || Run.httpd.flags & Httpd_Unix) {
                        if (Run.dommonitcredentials) {
                                Auth_T c;
                                for (c = Run.httpd.credentials; c; c = c->next) {
                                        if (c->digesttype == Digest_Cleartext && ! c->is_readonly) {
                                                Run.mmonitcredentials = c;
                                                break;
                                        }
                                }
                                if (! Run.mmonitcredentials)
                                        LogWarning("M/Monit registration with credentials enabled, but no suitable credentials found in monit configuration file -- please add 'allow user:password' option to 'set httpd' statement\n");
                        }
                } else {
                        LogWarning("M/Monit enabled but no httpd allowed -- please add 'set httpd' statement\n");
                }
        }

        /* Check the sanity of any dependency graph */
        check_depend();

#ifdef HAVE_OPENSSL
        Ssl_setFipsMode(Run.fipsEnabled);
#endif
}


/*
 * Create a new service object and add any current objects to the
 * service list.
 */
static Service_T createservice(Service_Type type, char *name, char *value, boolean_t (*check)(Service_T s)) {
        ASSERT(name);
        ASSERT(value);

        check_name(name);

        if (current)
                addservice(current);

        NEW(current);

        current->type = type;

        NEW(current->inf);
        Util_resetInfo(current);

        if (type == Service_Program) {
                NEW(current->program);
                current->program->args = command;
                command = NULL;
                current->program->timeout = PROGRAM_TIMEOUT;
        }

        /* Set default values */
        current->monitor = Monitor_Init;
        current->mode    = Monitor_Active;
        current->name    = name;
        current->check   = check;
        current->path    = value;

        /* Initialize general event handlers */
        addeventaction(&(current)->action_DATA,     Action_Alert,     Action_Alert);
        addeventaction(&(current)->action_EXEC,     Action_Alert,     Action_Alert);
        addeventaction(&(current)->action_INVALID,  Action_Restart,   Action_Alert);

        /* Initialize internal event handlers */
        addeventaction(&(current)->action_MONIT_START,  Action_Start, Action_Ignored);
        addeventaction(&(current)->action_MONIT_STOP,   Action_Stop,  Action_Ignored);
        addeventaction(&(current)->action_MONIT_RELOAD, Action_Start, Action_Ignored);
        addeventaction(&(current)->action_ACTION,       Action_Alert, Action_Ignored);

        gettimeofday(&current->collected, NULL);

        return current;
}


/*
 * Add a service object to the servicelist
 */
static void addservice(Service_T s) {
        ASSERT(s);

        // Test sanity check
        switch (s->type) {
                case Service_Host:
                        // Verify that a remote service has a port or an icmp list
                        if (! s->portlist && ! s->icmplist) {
                                LogError("'check host' statement is incomplete: Please specify a port number to test\n or an icmp test at the remote host: '%s'\n", s->name);
                                cfg_errflag++;
                        }
                        break;
                case Service_Program:
                        // Verify that a program test has a status test
                        if (! s->statuslist) {
                                LogError("'check program %s' is incomplete: Please add an 'if status != n' test\n", s->name);
                                cfg_errflag++;
                        }
                        // Create the Command object
                        s->program->C = Command_new(s->path, NULL);
                        // Append any arguments
                        for (int i = 1; i < s->program->args->length; i++)
                                Command_appendArgument(s->program->C, s->program->args->arg[i]);
                        if (s->program->args->has_uid)
                                Command_setUid(s->program->C, s->program->args->uid);
                        if (s->program->args->has_gid)
                                Command_setGid(s->program->C, s->program->args->gid);
                        break;
                case Service_Net:
                        if (! s->linkstatuslist) {
                                // Add link status test if not defined
                                addeventaction(&(linkstatusset).action, Action_Alert, Action_Alert);
                                addlinkstatus(s, &linkstatusset);
                        }
                        break;
                case Service_Filesystem:
                        if (! s->fsflaglist) {
                                // Add filesystem flags change test if not defined
                                addeventaction(&(fsflagset).action, Action_Alert, Action_Ignored);
                                addfsflag(&fsflagset);
                        }
                        break;
                case Service_Directory:
                case Service_Fifo:
                case Service_File:
                case Service_Process:
                        if (! s->nonexistlist) {
                                // Add existence test if not defined
                                addeventaction(&(nonexistset).action, Action_Restart, Action_Alert);
                                addnonexist(&nonexistset);
                        }
                        break;
                default:
                        break;
        }

        /* Add the service to the end of the service list */
        if (tail != NULL) {
                tail->next = s;
                tail->next_conf = s;
        } else {
                servicelist = s;
                servicelist_conf = s;
        }
        tail = s;
}


/*
 * Add entry to service group list
 */
static void addservicegroup(char *name) {
        ServiceGroup_T g;
        ServiceGroupMember_T m;

        ASSERT(name);

        /* Check if service group with the same name is defined already */
        for (g = servicegrouplist; g; g = g->next)
                if (IS(g->name, name))
                        break;

        if (! g) {
                NEW(g);
                g->name = Str_dup(name);
                g->next = servicegrouplist;
                servicegrouplist = g;
        }

        NEW(m);
        m->name = Str_dup(current->name);
        m->next = g->members;
        g->members = m;
}


/*
 * Add a dependant entry to the current service dependant list
 *
 */
static void adddependant(char *dependant) {
        Dependant_T d;

        ASSERT(dependant);

        NEW(d);

        if (current->dependantlist)
                d->next = current->dependantlist;

        d->dependant = dependant;
        current->dependantlist = d;

}


/*
 * Add the given mailaddress with the appropriate alert notification
 * values and mail attributes to the given mailinglist.
 */
static void addmail(char *mailto, Mail_T f, Mail_T *l) {
        Mail_T m;

        ASSERT(mailto);

        NEW(m);
        m->to       = mailto;
        m->from     = f->from;
        m->subject  = f->subject;
        m->message  = f->message;
        m->events   = f->events;
        m->reminder = f->reminder;

        m->next = *l;
        *l = m;

        reset_mailset();
}


/*
 * Add the given portset to the current service's portlist
 */
static void addport(Port_T *list, Port_T port) {
        ASSERT(port);

        Port_T p;
        NEW(p);
        p->port               = port->port;
        p->type               = port->type;
        p->socket             = port->socket;
        p->family             = port->family;
        p->action             = port->action;
        p->timeout            = port->timeout;
        p->retry              = port->retry;
        p->request            = port->request;
        p->generic            = port->generic;
        p->protocol           = port->protocol;
        p->pathname           = port->pathname;
        p->hostname           = port->hostname;
        p->url_request        = port->url_request;
        p->request_checksum   = port->request_checksum;
        p->request_hostheader = port->request_hostheader;
        p->http_headers       = port->http_headers;
        p->version            = port->version;
        p->operator           = port->operator;
        p->status             = port->status;
        memcpy(&p->ApacheStatus, &port->ApacheStatus, sizeof(struct apache_status));

        if (p->request_checksum) {
                cleanup_hash_string(p->request_checksum);
                if (strlen(p->request_checksum) == 32)
                        p->request_hashtype = Hash_Md5;
                else if (strlen(p->request_checksum) == 40)
                        p->request_hashtype = Hash_Sha1;
                else
                        yyerror2("invalid checksum [%s]", p->request_checksum);
        } else {
                p->request_hashtype = 0;
        }

        if (port->SSL.use_ssl == true) {
#ifdef HAVE_OPENSSL
                if (port->SSL.certmd5 != NULL) {
                        p->SSL.certmd5 = port->SSL.certmd5;
                        cleanup_hash_string(p->SSL.certmd5);
                }
                p->SSL.use_ssl = true;
                p->SSL.version = port->SSL.version;
#else
                yyerror("SSL check cannot be activated -- SSL disabled");
#endif
        }
        p->maxforward = port->maxforward;
        p->next = *list;
        *list = p;

        reset_portset();

}


/*
 * Add a new resource object to the current service resource list
 */
static void addresource(Resource_T rr) {
        Resource_T r;

        ASSERT(rr);

        NEW(r);
        if (! Run.doprocess)
                yyerror("Cannot activate service check. The process status engine was disabled. On certain systems you must run monit as root to utilize this feature)\n");
        r->resource_id = rr->resource_id;
        r->limit       = rr->limit;
        r->action      = rr->action;
        r->operator    = rr->operator;
        r->next        = current->resourcelist;

        current->resourcelist = r;
        reset_resourceset();
}


/*
 * Add a new file object to the current service timestamp list
 */
static void addtimestamp(Timestamp_T ts, boolean_t notime) {
        Timestamp_T t;

        ASSERT(ts);

        NEW(t);
        t->operator     = ts->operator;
        t->time         = ts->time;
        t->action       = ts->action;
        t->test_changes = ts->test_changes;

        if (t->test_changes || notime) {
                if (! File_exist(current->path))
                        DEBUG("The path '%s' used in the TIMESTAMP statement refer to a non-existing object\n", current->path);
                else if (! (t->timestamp = file_getTimestamp(current->path, S_IFDIR|S_IFREG)))
                        yyerror2("Cannot get the timestamp for '%s'", current->path);
        }

        t->next = current->timestamplist;
        current->timestamplist = t;

        reset_timestampset();
}


/*
 * Add a new object to the current service actionrate list
 */
static void addactionrate(ActionRate_T ar) {
        ActionRate_T a;

        ASSERT(ar);

        if (ar->count > ar->cycle)
                yyerror2("The number of restarts must be less than poll cycles");
        if (ar->count <= 0 || ar->cycle <= 0)
                yyerror2("Zero or negative values not allowed in a action rate statement");

        NEW(a);
        a->count  = ar->count;
        a->cycle  = ar->cycle;
        a->action = ar->action;

        a->next = current->actionratelist;
        current->actionratelist = a;

        reset_actionrateset();
}



/*
 * Add a new Size object to the current service size list
 */
static void addsize(Size_T ss) {
        Size_T s;
        struct stat buf;

        ASSERT(ss);

        NEW(s);
        s->operator     = ss->operator;
        s->size         = ss->size;
        s->action       = ss->action;
        s->test_changes = ss->test_changes;
        /* Get the initial size for future comparision, if the file exists */
        if (s->test_changes) {
                s->initialized = ! stat(current->path, &buf);
                if (s->initialized)
                        s->size = (unsigned long long)buf.st_size;
        }

        s->next = current->sizelist;
        current->sizelist = s;

        reset_sizeset();
}


/*
 * Add a new Uptime object to the current service uptime list
 */
static void adduptime(Uptime_T uu) {
        Uptime_T u;

        ASSERT(uu);

        NEW(u);
        u->operator = uu->operator;
        u->uptime = uu->uptime;
        u->action = uu->action;

        u->next = current->uptimelist;
        current->uptimelist = u;

        reset_uptimeset();
}


/*
 * Add a new Pid object to the current service pid list
 */
static void addpid(Pid_T pp) {
        ASSERT(pp);

        Pid_T p;
        NEW(p);
        p->action = pp->action;

        p->next = current->pidlist;
        current->pidlist = p;

        reset_pidset();
}


/*
 * Add a new PPid object to the current service ppid list
 */
static void addppid(Pid_T pp) {
        ASSERT(pp);

        Pid_T p;
        NEW(p);
        p->action = pp->action;

        p->next = current->ppidlist;
        current->ppidlist = p;

        reset_ppidset();
}


/*
 * Add a new Fsflag object to the current service fsflag list
 */
static void addfsflag(Fsflag_T ff) {
        ASSERT(ff);

        Fsflag_T f;
        NEW(f);
        f->action = ff->action;

        f->next = current->fsflaglist;
        current->fsflaglist = f;

        reset_fsflagset();
}


/*
 * Add a new Nonexist object to the current service list
 */
static void addnonexist(Nonexist_T ff) {
        ASSERT(ff);

        Nonexist_T f;
        NEW(f);
        f->action = ff->action;

        f->next = current->nonexistlist;
        current->nonexistlist = f;

        reset_nonexistset();
}


/*
 * Set Checksum object in the current service
 */
static void addchecksum(Checksum_T cs) {
        ASSERT(cs);

        cs->initialized = true;

        if (! *cs->hash) {
                if (cs->type == Hash_Unknown)
                        cs->type = Hash_Default;
                if (! (Util_getChecksum(current->path, cs->type, cs->hash, sizeof(cs->hash)))) {
                        /* If the file doesn't exist, set dummy value */
                        snprintf(cs->hash, sizeof(cs->hash), cs->type == Hash_Md5 ? "00000000000000000000000000000000" : "0000000000000000000000000000000000000000");
                        cs->initialized = false;
                        yywarning2("Cannot compute a checksum for file %s", current->path);
                }
        }

        int len = cleanup_hash_string(cs->hash);

        if (cs->type == Hash_Unknown) {
                if (len == 32) {
                        cs->type = Hash_Md5;
                } else if (len == 40) {
                        cs->type = Hash_Sha1;
                } else {
                        yyerror2("Unknown checksum type [%s] for file %s", cs->hash, current->path);
                        reset_checksumset();
                        return;
                }
        } else if ((cs->type == Hash_Md5 && len != 32) || (cs->type == Hash_Sha1 && len != 40)) {
                yyerror2("Invalid checksum [%s] for file %s", cs->hash, current->path);
                reset_checksumset();
                return;
        }

        Checksum_T c;
        NEW(c);
        c->type         = cs->type;
        c->test_changes = cs->test_changes;
        c->initialized  = cs->initialized;
        c->action       = cs->action;
        snprintf(c->hash, sizeof(c->hash), "%s", cs->hash);

        current->checksum = c;

        reset_checksumset();

}


/*
 * Set Perm object in the current service
 */
static void addperm(Perm_T ps) {
        ASSERT(ps);

        Perm_T p;
        NEW(p);
        p->action = ps->action;
        p->test_changes = ps->test_changes;
        if (p->test_changes) {
                if (! File_exist(current->path))
                        DEBUG("The path '%s' used in the PERMISSION statement refer to a non-existing object\n", current->path);
                else if ((p->perm = File_mod(current->path)) < 0)
                        yyerror2("Cannot get the timestamp for '%s'", current->path);
                else
                        p->perm &= 07777;
        } else {
                p->perm = ps->perm;
        }
        current->perm = p;
        reset_permset();
}


static void addlinkstatus(Service_T s, LinkStatus_T L) {
        ASSERT(L);
        
        LinkStatus_T l;
        NEW(l);
        l->action = L->action;
        
        l->next = s->linkstatuslist;
        s->linkstatuslist = l;
        
        reset_linkstatusset();
}


static void addlinkspeed(Service_T s, LinkSpeed_T L) {
        ASSERT(L);
        
        LinkSpeed_T l;
        NEW(l);
        l->action = L->action;
        
        l->next = s->linkspeedlist;
        s->linkspeedlist = l;
        
        reset_linkspeedset();
}


static void addlinksaturation(Service_T s, LinkSaturation_T L) {
        ASSERT(L);
        
        LinkSaturation_T l;
        NEW(l);
        l->operator = L->operator;
        l->limit = L->limit;
        l->action = L->action;
        
        l->next = s->linksaturationlist;
        s->linksaturationlist = l;
        
        reset_linksaturationset();
}


/*
 * Return Bandwidth object
 */
static void addbandwidth(Bandwidth_T *list, Bandwidth_T b) {
        ASSERT(list);
        ASSERT(b);

        if (b->rangecount * b->range > 24 * Time_Hour) {
                yyerror2("Maximum range for total test is 24 hours");
        } else if (b->range == Time_Minute && b->rangecount > 60) {
                yyerror2("Maximum value for [minute(s)] unit is 60");
        } else if (b->range == Time_Hour && b->rangecount > 24) {
                yyerror2("Maximum value for [hour(s)] unit is 24");
        } else if (b->range == Time_Day && b->rangecount > 1) {
                yyerror2("Maximum value for [day(s)] unit is 1");
        } else {
                if (b->range == Time_Day) {
                        // translate last day -> last 24 hours
                        b->rangecount = 24;
                        b->range = Time_Hour;
                }
                Bandwidth_T bandwidth;
                NEW(bandwidth);
                bandwidth->operator = b->operator;
                bandwidth->limit = b->limit;
                bandwidth->rangecount = b->rangecount;
                bandwidth->range = b->range;
                bandwidth->action = b->action;
                bandwidth->next = *list;
                *list = bandwidth;
        }
        reset_bandwidthset();
}


static void appendmatch(Match_T *list, Match_T item) {
        if (*list) {
                /* Find the end of the list (keep the same patterns order as in the config file) */
                Match_T last;
                for (last = *list; last->next; last = last->next)
                        ;
                last->next = item;
        } else {
                *list = item;
        }
}


/*
 * Set Match object in the current service
 */
static void addmatch(Match_T ms, int actionnumber, int linenumber) {
        Match_T m;
        int     reg_return;

        ASSERT(ms);

        NEW(m);
#ifdef HAVE_REGEX_H
        NEW(m->regex_comp);
#endif

        m->match_string = ms->match_string;
        m->match_path   = ms->match_path ? Str_dup(ms->match_path) : NULL;
        m->action       = ms->action;
        m->not          = ms->not;
        m->ignore       = ms->ignore;
        m->next         = NULL;

        addeventaction(&(m->action), actionnumber, Action_Ignored);

#ifdef HAVE_REGEX_H
        reg_return = regcomp(m->regex_comp, ms->match_string, REG_NOSUB|REG_EXTENDED);

        if (reg_return != 0) {
                char errbuf[STRLEN];
                regerror(reg_return, ms->regex_comp, errbuf, STRLEN);
                if (m->match_path != NULL)
                        yyerror2("Regex parsing error: %s on line %i of", errbuf, linenumber);
                else
                        yyerror2("Regex parsing error: %s", errbuf);
        }
#endif
        appendmatch(m->ignore ? &current->matchignorelist : &current->matchlist, m);
}


static void addmatchpath(Match_T ms, Action_Type actionnumber) {

        FILE *handle;
        command_t savecommand = NULL;
        char buf[2048];
        int linenumber = 0;

        ASSERT(ms->match_path);

        handle = fopen(ms->match_path, "r");
        if (handle == NULL) {
                yyerror2("Cannot read regex match file (%s)", ms->match_path);
                return;
        }

        while (! feof(handle)) {
                size_t len;

                linenumber++;

                if (! fgets(buf, 2048, handle))
                        continue;

                len = strlen(buf);

                if (len == 0 || buf[0] == '\n')
                        continue;

                if (buf[len-1] == '\n')
                        buf[len-1] = 0;

                ms->match_string = Str_dup(buf);

                /* The addeventaction() called from addmatch() will reset the
                 * command1 to NULL, but we need to duplicate the command for
                 * each line, thus need to save it here */
                if (actionnumber == Action_Exec) {
                        if (command1 == NULL) {
                                ASSERT(savecommand);
                                command1 = savecommand;
                        }
                        savecommand = copycommand(command1);
                }
                
                addmatch(ms, actionnumber, linenumber);
        }
        
        if (actionnumber == Action_Exec && savecommand)
                gccmd(&savecommand);
        
        fclose(handle);
}


/*
 * Set exit status test object in the current service
 */
static void addstatus(Status_T status) {
        Status_T s;
        ASSERT(status);
        NEW(s);
        s->initialized = status->initialized;
        s->return_value = status->return_value;
        s->operator = status->operator;
        s->action = status->action;
        s->next = current->statuslist;
        current->statuslist = s;

        reset_statusset();
}


/*
 * Set Uid object in the current service
 */
static Uid_T adduid(Uid_T u) {
        ASSERT(u);

        Uid_T uid;
        NEW(uid);
        uid->uid = u->uid;
        uid->action = u->action;
        reset_uidset();
        return uid;
}


/*
 * Set Gid object in the current service
 */
static Gid_T addgid(Gid_T g) {
        ASSERT(g);

        Gid_T gid;
        NEW(gid);
        gid->gid = g->gid;
        gid->action = g->action;
        reset_gidset();
        return gid;
}


/*
 * Add a new filesystem to the current service's filesystem list
 */
static void addfilesystem(Filesystem_T ds) {
        Filesystem_T dev;

        ASSERT(ds);

        NEW(dev);
        dev->resource           = ds->resource;
        dev->operator           = ds->operator;
        dev->limit_absolute     = ds->limit_absolute;
        dev->limit_percent      = ds->limit_percent;
        dev->action             = ds->action;

        dev->next               = current->filesystemlist;
        current->filesystemlist = dev;
        
        reset_filesystemset();

}


/*
 * Add a new icmp object to the current service's icmp list
 */
static void addicmp(Icmp_T is) {
        Icmp_T icmp;

        ASSERT(is);

        NEW(icmp);
        icmp->family       = is->family;
        icmp->type         = is->type;
        icmp->count        = is->count;
        icmp->timeout      = is->timeout;
        icmp->action       = is->action;
        icmp->is_available = false;
        icmp->response     = -1;

        icmp->next         = current->icmplist;
        current->icmplist  = icmp;

        reset_icmpset();
}


/*
 * Set EventAction object
 */
static void addeventaction(EventAction_T *_ea, Action_Type failed, Action_Type succeeded) {
        EventAction_T ea;

        ASSERT(_ea);

        NEW(ea);
        NEW(ea->failed);
        NEW(ea->succeeded);

        ea->failed->id     = failed;
        ea->failed->count  = rate1.count;
        ea->failed->cycles = rate1.cycles;
        if (failed == Action_Exec) {
                ASSERT(command1);
                ea->failed->exec = command1;
                command1 = NULL;
        }

        ea->succeeded->id     = succeeded;
        ea->succeeded->count  = rate2.count;
        ea->succeeded->cycles = rate2.cycles;
        if (succeeded == Action_Exec) {
                ASSERT(command2);
                ea->succeeded->exec = command2;
                command2 = NULL;
        }
        *_ea = ea;
        reset_rateset();
}


/*
 * Add a generic protocol handler to
 */
static void addgeneric(Port_T port, char *send, char *expect) {
        Generic_T g = port->generic;

        if (g == NULL) {
                NEW(g);
                port->generic = g;
        } else {
                while (g->next)
                        g = g->next;
                NEW(g->next);
                g = g->next;
        }

        if (send != NULL) {
                g->send = send;
                g->expect = NULL;
        } else if (expect != NULL) {
#ifdef HAVE_REGEX_H

                int   reg_return;
                NEW(g->expect);
                reg_return = regcomp(g->expect, expect, REG_NOSUB|REG_EXTENDED);
                FREE(expect);
                if (reg_return != 0) {
                        char errbuf[STRLEN];
                        regerror(reg_return, g->expect, errbuf, STRLEN);
                        yyerror2("Regex parsing error: %s", errbuf);
                }
#else
                g->expect = expect;
#endif
                g->send = NULL;
        }
}


/*
 * Add the current command object to the current service object's
 * start or stop program.
 */
static void addcommand(int what, unsigned timeout) {

        switch (what) {
                case START:   current->start = command; break;
                case STOP:    current->stop = command; break;
                case RESTART: current->restart = command; break;
        }

        command->timeout = timeout;
        
        command = NULL;

}


/*
 * Add a new argument to the argument list
 */
static void addargument(char *argument) {

        ASSERT(argument);

        if (! command) {

                NEW(command);
                check_exec(argument);

        }

        command->arg[command->length++] = argument;
        command->arg[command->length] = NULL;

        if (command->length >= ARGMAX)
                yyerror("Exceeded maximum number of program arguments");

}


/*
 * Setup a url request for the current port object
 */
static void prepare_urlrequest(URL_T U) {

        ASSERT(U);

        portset.protocol = Protocol_get(Protocol_HTTP);

        if (urlrequest == NULL)
                NEW(urlrequest);
        urlrequest->url = U;
        portset.hostname = Str_dup(U->hostname);
        check_hostname(portset.hostname);
        portset.port = U->port;
        portset.url_request = urlrequest;
        portset.type = Socket_Tcp;
        portset.request = Str_cat("%s%s%s", U->path, U->query ? "?" : "", U->query ? U->query : "");
        /* Only the HTTP protocol is supported for URLs.
         See also the lexer if this is to be changed in
         the future */
        portset.protocol = Protocol_get(Protocol_HTTP);
        if (IS(U->protocol, "https"))
                portset.SSL.use_ssl = true;

}


/*
 * Set the url request for a port
 */
static void  seturlrequest(int operator, char *regex) {

        ASSERT(regex);

        if (! urlrequest)
                NEW(urlrequest);
        urlrequest->operator = operator;
        #ifdef HAVE_REGEX_H
        {
                int reg_return;
                NEW(urlrequest->regex);
                reg_return = regcomp(urlrequest->regex, regex, REG_NOSUB|REG_EXTENDED);
                if (reg_return != 0) {
                        char errbuf[STRLEN];
                        regerror(reg_return, urlrequest->regex, errbuf, STRLEN);
                        yyerror2("Regex parsing error: %s", errbuf);
                }
        }
        #else
        urlrequest->regex = Str_dup(regex);
        #endif

}


/*
 * Add a new data recipient server to the mmonit server list
 */
static void addmmonit(URL_T url, int timeout, Ssl_Version sslversion, char *certmd5) {
        Mmonit_T c;

        ASSERT(url);

        NEW(c);
        c->url = url;
        if (IS(c->url->protocol, "https")) {
#ifdef HAVE_OPENSSL
                c->ssl.use_ssl = true;
                c->ssl.version = (sslversion == SSL_Disabled) ? SSL_Auto : sslversion;
                if (certmd5) {
                        c->ssl.certmd5 = certmd5;
                        cleanup_hash_string(c->ssl.certmd5);
                }
#else
                yyerror("SSL check cannot be activated -- SSL disabled");
#endif
        }
        c->timeout = timeout;
        c->next = NULL;

        if (Run.mmonits) {
                Mmonit_T C;
                for (C = Run.mmonits; C->next; C = C->next)
                        /* Empty */ ;
                C->next = c;
        } else {
                Run.mmonits = c;
        }
}


/*
 * Add a new smtp server to the mail server list
 */
static void addmailserver(MailServer_T mailserver) {

        MailServer_T s;

        ASSERT(mailserver->host);

        NEW(s);
        s->host        = mailserver->host;
        s->port        = mailserver->port;
        s->username    = mailserver->username;
        s->password    = mailserver->password;
        s->ssl.use_ssl = mailserver->ssl.use_ssl;
        s->ssl.version = mailserver->ssl.version;
        s->ssl.certmd5 = mailserver->ssl.certmd5;

        s->next = NULL;

        if (Run.mailservers) {
                MailServer_T l;
                for (l = Run.mailservers; l->next; l = l->next)
                        /* empty */;
                l->next = s;
        } else {
                Run.mailservers = s;
        }

        reset_mailserverset();
}


/*
 * Return uid if found on the system. If the parameter user is NULL
 * the uid parameter is used for looking up the user id on the system,
 * otherwise the user parameter is used.
 */
static uid_t get_uid(char *user, uid_t uid) {
        struct passwd *pwd;

        if (user) {
                pwd = getpwnam(user);

                if (! pwd) {
                        yyerror2("Requested user not found on the system");
                        return(0);
                }

        } else {

                if (! (pwd = getpwuid(uid))) {
                        yyerror2("Requested uid not found on the system");
                        return(0);
                }
        }

        return(pwd->pw_uid);

}


/*
 * Return gid if found on the system. If the parameter group is NULL
 * the gid parameter is used for looking up the group id on the system,
 * otherwise the group parameter is used.
 */
static gid_t get_gid(char *group, gid_t gid) {
        struct group *grd;

        if (group) {
                grd = getgrnam(group);

                if (! grd) {
                        yyerror2("Requested group not found on the system");
                        return(0);
                }

        } else {

                if (! (grd = getgrgid(gid))) {
                        yyerror2("Requested gid not found on the system");
                        return(0);
                }

        }

        return(grd->gr_gid);

}


/*
 * Add a new user id to the current command object.
 */
static void addeuid(uid_t uid) {
        if (! getuid()) {
                command->has_uid = true;
                command->uid = uid;
        } else {
                yyerror("UID statement requires root privileges");
        }
}


/*
 * Add a new group id to the current command object.
 */
static void addegid(gid_t gid) {
        if (! getuid()) {
                command->has_gid = true;
                command->gid = gid;
        } else {
                yyerror("GID statement requires root privileges");
        }
}


/*
 * Reset the logfile if changed
 */
static void setlogfile(char *logfile) {
        if (Run.logfile) {
                if (IS(Run.logfile, logfile)) {
                        FREE(logfile);
                        return;
                } else {
                        FREE(Run.logfile);
                }
        }
        Run.logfile = logfile;
}


/*
 * Reset the pidfile if changed
 */
static void setpidfile(char *pidfile) {
        if (Run.pidfile) {
                if (IS(Run.pidfile, pidfile)) {
                        FREE(pidfile);
                        return;
                } else {
                        FREE(Run.pidfile);
                }
        }
        Run.pidfile = pidfile;
}


/*
 * Read a apache htpasswd file and add credentials found for username
 */
static void addhtpasswdentry(char *filename, char *username, Digest_Type dtype) {
        char *ht_username = NULL;
        char *ht_passwd = NULL;
        char buf[STRLEN];
        FILE *handle = NULL;
        int credentials_added = 0;

        ASSERT(filename);

        handle = fopen(filename, "r");

        if ( handle == NULL ) {
                if (username != NULL)
                        yyerror2("Cannot read htpasswd (%s)", filename);
                else
                        yyerror2("Cannot read htpasswd", filename);
                return;
        }

        while (! feof(handle)) {
                char *colonindex = NULL;

                if (! fgets(buf, STRLEN, handle))
                        continue;

                Str_rtrim(buf);
                Str_curtail(buf, "#");

                if ( NULL == (colonindex = strchr(buf, ':')))
                continue;

                ht_passwd = Str_dup(colonindex+1);
                *colonindex = '\0';

                /* In case we have a file in /etc/passwd or /etc/shadow style we
                 *  want to remove ":.*$" and Crypt and MD5 hashed dont have a colon
                 */

                if ( (NULL != (colonindex = strchr(ht_passwd, ':'))) && ( dtype != Digest_Cleartext) )
                *colonindex = '\0';

                ht_username = Str_dup(buf);

                if (username == NULL) {
                        if (addcredentials(ht_username, ht_passwd, dtype, false))
                                credentials_added++;
                } else if (Str_cmp(username, ht_username) == 0)  {
                        if (addcredentials(ht_username, ht_passwd, dtype, false))
                                credentials_added++;
                } else {
                        FREE(ht_passwd);
                        FREE(ht_username);
                }
        }

        if (credentials_added == 0) {
                if ( username == NULL )
                        yywarning2("htpasswd file (%s) has no usable credentials", filename);
                else
                        yywarning2("htpasswd file (%s) has no usable credentials for user %s", filename, username);
        }
        fclose(handle);
}


#ifdef HAVE_LIBPAM
static void addpamauth(char* groupname, int readonly) {
        Auth_T prev = NULL;

        ASSERT(groupname);

        if (! Run.httpd.credentials)
                NEW(Run.httpd.credentials);

        Auth_T c = Run.httpd.credentials;
        do {
                if (c->groupname != NULL && IS(c->groupname, groupname)) {
                        yywarning2("PAM group %s was added already, entry ignored", groupname);
                        FREE(groupname);
                        return;
                }
                prev = c;
                c = c->next;
        } while (c != NULL);

        NEW(prev->next);
        c = prev->next;

        c->next        = NULL;
        c->uname       = NULL;
        c->passwd      = NULL;
        c->groupname   = groupname;
        c->digesttype  = Digest_Pam;
        c->is_readonly = readonly;

        DEBUG("Adding PAM group '%s'\n", groupname);

        return;
}
#endif


/*
 * Add Basic Authentication credentials
 */
static boolean_t addcredentials(char *uname, char *passwd, Digest_Type dtype, boolean_t readonly) {
        Auth_T c;

        ASSERT(uname);
        ASSERT(passwd);

        if (! Run.httpd.credentials) {
                NEW(Run.httpd.credentials);
                c = Run.httpd.credentials;
        } else {

                if (Util_getUserCredentials(uname) != NULL) {
                        yywarning2("Credentials for user %s were already added, entry ignored", uname);
                        FREE(uname);
                        FREE(passwd);
                        return false;
                }

                c = Run.httpd.credentials;

                while (c->next != NULL)
                        c = c->next;

                NEW(c->next);
                c = c->next;

        }

        c->next        = NULL;
        c->uname       = uname;
        c->passwd      = passwd;
        c->groupname   = NULL;
        c->digesttype  = dtype;
        c->is_readonly = readonly;

        DEBUG("Adding credentials for user '%s'\n", uname);

        return true;

}


/*
 * Set the syslog and the facilities to be used
 */
static void setsyslog(char *facility) {

        if (! Run.logfile || ihp.logfile) {
                ihp.logfile = true;
                setlogfile(Str_dup("syslog"));
                Run.use_syslog = true;
                Run.dolog = true;
        }

        if (facility) {
                if (IS(facility,"log_local0"))
                        Run.facility = LOG_LOCAL0;
                else if (IS(facility, "log_local1"))
                        Run.facility = LOG_LOCAL1;
                else if (IS(facility, "log_local2"))
                        Run.facility = LOG_LOCAL2;
                else if (IS(facility, "log_local3"))
                        Run.facility = LOG_LOCAL3;
                else if (IS(facility, "log_local4"))
                        Run.facility = LOG_LOCAL4;
                else if (IS(facility, "log_local5"))
                        Run.facility = LOG_LOCAL5;
                else if (IS(facility, "log_local6"))
                        Run.facility = LOG_LOCAL6;
                else if (IS(facility, "log_local7"))
                        Run.facility = LOG_LOCAL7;
                else if (IS(facility, "log_daemon"))
                        Run.facility = LOG_DAEMON;
                else
                        yyerror2("Invalid syslog facility");
        } else {
                Run.facility = LOG_USER;
        }

}


/*
 * Reset the current mailset for reuse
 */
static void reset_mailset() {
        memset(&mailset, 0, sizeof(struct mymail));
}


/*
 * Reset the mailserver set to default values
 */
static void reset_mailserverset() {
        memset(&mailserverset, 0, sizeof(struct mymailserver));
        mailserverset.port = PORT_SMTP;
        mailserverset.ssl.use_ssl = false;
        mailserverset.ssl.version = SSL_Auto;
}


/*
 * Reset the Port set to default values
 */
static void reset_portset() {
        memset(&portset, 0, sizeof(struct myport));
        portset.socket = -1;
        portset.type = Socket_Tcp;
        portset.family = Socket_Ip;
        portset.SSL.version = SSL_Auto;
        portset.timeout = NET_TIMEOUT;
        portset.retry = 1;
        portset.maxforward = 70;
        portset.operator = Operator_Less;
        portset.status = 400;
        urlrequest = NULL;
}


/*
 * Reset the Proc set to default values
 */
static void reset_resourceset() {
        resourceset.resource_id = 0;
        resourceset.limit = 0;
        resourceset.action = NULL;
        resourceset.operator = Operator_Equal;
}


/*
 * Reset the Timestamp set to default values
 */
static void reset_timestampset() {
        timestampset.operator = Operator_Equal;
        timestampset.time = 0;
        timestampset.test_changes = false;
        timestampset.action = NULL;
}


/*
 * Reset the ActionRate set to default values
 */
static void reset_actionrateset() {
        actionrateset.count = 0;
        actionrateset.cycle = 0;
        actionrateset.action = NULL;
}


/*
 * Reset the Size set to default values
 */
static void reset_sizeset() {
        sizeset.operator = Operator_Equal;
        sizeset.size = 0;
        sizeset.test_changes = false;
        sizeset.action = NULL;
}


/*
 * Reset the Uptime set to default values
 */
static void reset_uptimeset() {
        uptimeset.operator = Operator_Equal;
        uptimeset.uptime = 0;
        uptimeset.action = NULL;
}


static void reset_linkstatusset() {
        linkstatusset.action = NULL;
}


static void reset_linkspeedset() {
        linkspeedset.action = NULL;
}


static void reset_linksaturationset() {
        linksaturationset.limit = 0.;
        linksaturationset.operator = Operator_Equal;
        linksaturationset.action = NULL;
}


/*
 * Reset the Bandwidth set to default values
 */
static void reset_bandwidthset() {
        bandwidthset.operator = Operator_Equal;
        bandwidthset.limit = 0ULL;
        bandwidthset.action = NULL;
}


/*
 * Reset the Pid set to default values
 */
static void reset_pidset() {
        pidset.action = NULL;
}


/*
 * Reset the PPid set to default values
 */
static void reset_ppidset() {
        ppidset.action = NULL;
}


/*
 * Reset the Fsflag set to default values
 */
static void reset_fsflagset() {
        fsflagset.action = NULL;
}


/*
 * Reset the Nonexist set to default values
 */
static void reset_nonexistset() {
        nonexistset.action = NULL;
}


/*
 * Reset the Checksum set to default values
 */
static void reset_checksumset() {
        checksumset.type         = Hash_Unknown;
        checksumset.test_changes = false;
        checksumset.action       = NULL;
        *checksumset.hash        = 0;
}


/*
 * Reset the Perm set to default values
 */
static void reset_permset() {
        permset.test_changes = false;
        permset.perm = 0;
        permset.action = NULL;
}


/*
 * Reset the Status set to default values
 */
static void reset_statusset() {
        statusset.initialized = false;
        statusset.return_value = 0;
        statusset.operator = Operator_Equal;
        statusset.action = NULL;
}


/*
 * Reset the Uid set to default values
 */
static void reset_uidset() {
        uidset.uid = 0;
        uidset.action = NULL;
}


/*
 * Reset the Gid set to default values
 */
static void reset_gidset() {
        gidset.gid = 0;
        gidset.action = NULL;
}


/*
 * Reset the Filesystem set to default values
 */
static void reset_filesystemset() {
        filesystemset.resource = 0;
        filesystemset.operator = Operator_Equal;
        filesystemset.limit_absolute = -1;
        filesystemset.limit_percent = -1;
        filesystemset.action = NULL;
}


/*
 * Reset the ICMP set to default values
 */
static void reset_icmpset() {
        icmpset.type = ICMP_ECHO;
        icmpset.count = ICMP_ATTEMPT_COUNT;
        icmpset.timeout = NET_TIMEOUT;
        icmpset.action = NULL;
}


/*
 * Reset the Rate set to default values
 */
static void reset_rateset() {
        rate1.count  = 1;
        rate1.cycles = 1;

        rate2.count  = 1;
        rate2.cycles = 1;
}


/* ---------------------------------------------------------------- Checkers */


/*
 * Check for unique service name
 */
static void check_name(char *name) {
        ASSERT(name);

        if (Util_existService(name) || (current && IS(name, current->name)))
                yyerror2("Service name conflict, %s already defined", name);
        if (name && *name == '/')
                yyerror2("Service name '%s' must not start with '/' -- ", name);
}


/*
 * Permission statement semantic check
 */
static int check_perm(int perm) {
        int result;
        char *status;
        char buf[STRLEN];

        snprintf(buf, STRLEN, "%d", perm);

        result = (int)strtol(buf, &status, 8);

        if (*status != '\0' || result < 0 || result > 07777)
                yyerror2("Permission statements must have an octal value between 0 and 7777");

        return result;
}


/*
 * Check hostname
 */
static void check_hostname(char *hostname) {
        ASSERT(hostname);
        if (! check_host(hostname))
                yywarning2("Hostname %s did not resolve", hostname);
}

/*
 * Check the dependency graph for errors
 * by doing a topological sort, thereby finding any cycles.
 * Assures that graph is a Directed Acyclic Graph (DAG).
 */
static void check_depend() {
        Service_T s;
        Service_T depends_on = NULL;
        Service_T* dlt = &depend_list; /* the current tail of it                                 */
        boolean_t done;                /* no unvisited nodes left?                               */
        boolean_t found_some;          /* last iteration found anything new ?                    */
        depend_list = NULL;            /* depend_list will be the topological sorted servicelist */

        do {
                done = true;
                found_some = false;
                for (s = servicelist; s; s = s->next) {
                        Dependant_T d;
                        if (s->visited)
                                continue;
                        done = false; // still unvisited nodes
                        depends_on = NULL;
                        for (d = s->dependantlist; d; d = d->next) {
                                Service_T dp = Util_getService(d->dependant);
                                if (! dp) {
                                        LogError("Depend service '%s' is not defined in the control file\n", d->dependant);
                                        exit(1);
                                }
                                if (! dp->visited) {
                                        depends_on = dp;
                                }
                        }

                        if (! depends_on) {
                                s->visited = true;
                                found_some = true;
                                *dlt = s;
                                dlt = &s->next_depend;
                        }
                }
        } while (found_some && ! done);

        if (! done) {
                ASSERT(depends_on);
                LogError("Found a depend loop in the control file involving the service '%s'\n", depends_on->name);
                exit(1);
        }

        ASSERT(depend_list);
        servicelist = depend_list;

        for (s = depend_list; s; s = s->next_depend)
                s->next = s->next_depend;

        reset_depend();
}


/*
 * Check if the executable exist
 */
static void check_exec(char *exec) {
        if (! File_exist(exec))
                yywarning2("Program does not exist:");
        else if (! File_isExecutable(exec))
                yywarning2("Program is not executable:");
}


/* Return a valid max forward value for SIP header */
static int verifyMaxForward(int mf) {
        int max = 70;

        if (mf >= 0 && mf <= 255)
                max = mf;
        else
                yywarning2("SIP max forward is outside the range [0..255]. Setting max forward to 70");

        return max;
}


/* -------------------------------------------------------------------- Misc */


/*
 * Cleans up an md5 string, tolower and remove byte separators
 */
static int cleanup_hash_string(char *hashstring) {
        int i = 0, j = 0;

        ASSERT(hashstring);

        while (hashstring[i] != '\0') {
                if (isxdigit((int) hashstring[i])) {
                        hashstring[j] = tolower((int)hashstring[i]);
                        j++;
                }
                i++;
        }
        hashstring[j] = '\0';
        return j;
}


/* Return deep copy of the command */
static command_t copycommand(command_t source) {
        int i;
        command_t copy = NULL;

        NEW(copy);
        copy->length = source->length;
        copy->has_uid = source->has_uid;
        copy->uid = source->uid;
        copy->has_gid = source->has_gid;
        copy->gid = source->gid;
        copy->timeout = source->timeout;
        for (i = 0; i < copy->length; i++)
        copy->arg[i] = Str_dup(source->arg[i]);
        copy->arg[copy->length] = NULL;

        return copy;
}

