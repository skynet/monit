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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
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


#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include "monit.h"
#include "alert.h"
#include "event.h"
#include "process.h"

// libmonit
#include "io/File.h"
#include "system/Time.h"

/**
 * Implementation of the event interface.
 *
 * @file
 */


/* ------------------------------------------------------------- Definitions */

EventTable_T Event_Table[] = {
        {Event_Action,     "Action done",               "Action done",                "Action done",              "Action done"},
        {Event_ByteIn,     "Download bytes exceeded",   "Download bytes ok",          "Download bytes changed",   "Download bytes not changed"},
        {Event_ByteOut,    "Upload bytes exceeded",     "Upload bytes ok",            "Upload bytes changed",     "Upload bytes not changed"},
        {Event_Checksum,   "Checksum failed",           "Checksum succeeded",         "Checksum changed",         "Checksum not changed"},
        {Event_Connection, "Connection failed",         "Connection succeeded",       "Connection changed",       "Connection not changed"},
        {Event_Content,    "Content failed",            "Content succeeded",          "Content match",            "Content doesn't match"},
        {Event_Data,       "Data access error",         "Data access succeeded",      "Data access changed",      "Data access not changed"},
        {Event_Exec,       "Execution failed",          "Execution succeeded",        "Execution changed",        "Execution not changed"},
        {Event_Fsflag,     "Filesystem flags failed",   "Filesystem flags succeeded", "Filesystem flags changed", "Filesystem flags not changed"},
        {Event_Gid,        "GID failed",                "GID succeeded",              "GID changed",              "GID not changed"},
        {Event_Heartbeat,  "Heartbeat failed",          "Heartbeat succeeded",        "Heartbeat changed",        "Heartbeat not changed"},
        {Event_Icmp,       "ICMP failed",               "ICMP succeeded",             "ICMP changed",             "ICMP not changed"},
        {Event_Instance,   "Monit instance failed",     "Monit instance succeeded",   "Monit instance changed",   "Monit instance not changed"},
        {Event_Invalid,    "Invalid type",              "Type succeeded",             "Type changed",             "Type not changed"},
        {Event_Link,       "Link down",                 "Link up",                    "Link changed",             "Link not changed"},
        {Event_Nonexist,   "Does not exist",            "Exists",                     "Existence changed",        "Existence not changed"},
        {Event_PacketIn,   "Download packets exceeded", "Download packets ok",        "Download packets changed", "Download packets not changed"},
        {Event_PacketOut,  "Upload packets exceeded",   "Upload packets ok",          "Upload packets changed",   "Upload packets not changed"},
        {Event_Permission, "Permission failed",         "Permission succeeded",       "Permission changed",       "Permission not changed"},
        {Event_Pid,        "PID failed",                "PID succeeded",              "PID changed",              "PID not changed"},
        {Event_PPid,       "PPID failed",               "PPID succeeded",             "PPID changed",             "PPID not changed"},
        {Event_Resource,   "Resource limit matched",    "Resource limit succeeded",   "Resource limit changed",   "Resource limit not changed"},
        {Event_Saturation, "Saturation exceeded",       "Saturation ok",              "Saturation changed",       "Saturation not changed"},
        {Event_Size,       "Size failed",               "Size succeeded",             "Size changed",             "Size not changed"},
        {Event_Speed,      "Speed failed",              "Speed ok",                   "Speed changed",            "Speed not changed"},
        {Event_Status,     "Status failed",             "Status succeeded",           "Status changed",           "Status not changed"},
        {Event_Timeout,    "Timeout",                   "Timeout recovery",           "Timeout changed",          "Timeout not changed"},
        {Event_Timestamp,  "Timestamp failed",          "Timestamp succeeded",        "Timestamp changed",        "Timestamp not changed"},
        {Event_Uid,        "UID failed",                "UID succeeded",              "UID changed",              "UID not changed"},
        {Event_Uptime,     "Uptime failed",             "Uptime succeeded",           "Uptime changed",           "Uptime not changed"},
        /* Virtual events */
        {Event_Null,       "No Event",                  "No Event",                   "No Event",                 "No Event"}
};


/* -------------------------------------------------------------- Prototypes */


static void handle_event(Service_T, Event_T);
static void handle_action(Event_T, Action_T);
static void Event_queue_add(Event_T);
static void Event_queue_update(Event_T, const char *);


/* ------------------------------------------------------------------ Public */


/**
 * Post a new Event
 * @param service The Service the event belongs to
 * @param id The event identification
 * @param state The event state
 * @param action Description of the event action
 * @param s Optional message describing the event
 */
void Event_post(Service_T service, long id, State_Type state, EventAction_T action, char *s, ...) {
        ASSERT(service);
        ASSERT(action);
        ASSERT(s);
        ASSERT(state == State_Failed || state == State_Succeeded || state == State_Changed || state == State_ChangedNot);

        va_list ap;
        va_start(ap, s);
        char *message = Str_vcat(s, ap);
        va_end(ap);

        Event_T e = service->eventlist;
        if (! e) {
                /* Only first failed/changed event can initialize the queue for given event type, thus succeeded events are ignored until first error. */
                if (state == State_Succeeded || state == State_ChangedNot) {
                        DEBUG("'%s' %s\n", service->name, message);
                        FREE(message);
                        return;
                }

                /* Initialize event list and add first event. The manadatory informations
                 * are cloned so the event is as standalone as possible and may be saved
                 * to the queue without the dependency on the original service, thus
                 * persistent and managable across monit restarts */
                NEW(e);
                e->id = id;
                gettimeofday(&e->collected, NULL);
                e->source = Str_dup(service->name);
                e->mode = service->mode;
                e->type = service->type;
                e->state = State_Init;
                e->state_map = 1;
                e->action = action;
                e->message = message;
                service->eventlist = e;
        } else {
                /* Try to find the event with the same origin and type identification. Each service and each test have its own custom actions object, so we share actions object address to identify event source. */
                do {
                        if (e->action == action && e->id == id) {
                                gettimeofday(&e->collected, NULL);

                                /* Shift the existing event flags to the left and set the first bit based on actual state */
                                e->state_map <<= 1;
                                e->state_map |= ((state == State_Succeeded || state == State_ChangedNot) ? 0 : 1);

                                /* Update the message */
                                FREE(e->message);
                                e->message = message;
                                break;
                        }
                        e = e->next;
                } while (e);

                if (! e) {
                        /* Only first failed/changed event can initialize the queue for given event type, thus succeeded events are ignored until first error. */
                        if (state == State_Succeeded || state == State_ChangedNot) {
                                DEBUG("'%s' %s\n", service->name, message);
                                FREE(message);
                                return;
                        }

                        /* Event was not found in the pending events list, we will add it.
                         * The manadatory informations are cloned so the event is as standalone
                         * as possible and may be saved to the queue without the dependency on
                         * the original service, thus persistent and managable across monit
                         * restarts */
                        NEW(e);
                        e->id = id;
                        gettimeofday(&e->collected, NULL);
                        e->source = Str_dup(service->name);
                        e->mode = service->mode;
                        e->type = service->type;
                        e->state = State_Init;
                        e->state_map = 1;
                        e->action = action;
                        e->message = message;
                        e->next = service->eventlist;
                        service->eventlist = e;
                }
        }

        e->state_changed = Event_check_state(e, state);

        /* In the case that the state changed, update it and reset the counter */
        if (e->state_changed) {
                e->state = state;
                e->count = 1;
        } else
                e->count++;

        handle_event(service, e);
}


/* -------------------------------------------------------------- Properties */


/**
 * Get the Service where the event orginated
 * @param E An event object
 * @return The Service where the event orginated
 */
Service_T Event_get_source(Event_T E) {
        Service_T s = NULL;

        ASSERT(E);

        if (! (s = Util_getService(E->source)))
                LogError("Service %s not found in monit configuration\n", E->source);

        return s;
}


/**
 * Get the Service name where the event orginated
 * @param E An event object
 * @return The Service name where the event orginated
 */
char *Event_get_source_name(Event_T E) {
        ASSERT(E);
        return (E->source);
}


/**
 * Get the service type of the service where the event orginated
 * @param E An event object
 * @return The service type of the service where the event orginated
 */
int Event_get_source_type(Event_T E) {
        ASSERT(E);
        return (E->type);
}


/**
 * Get the Event timestamp
 * @param E An event object
 * @return The Event timestamp
 */
struct timeval *Event_get_collected(Event_T E) {
        ASSERT(E);
        return &E->collected;
}


/**
 * Get the Event raw state
 * @param E An event object
 * @return The Event raw state
 */
State_Type Event_get_state(Event_T E) {
        ASSERT(E);
        return E->state;
}


/**
 * Return the actual event state based on event state bitmap
 * and event ratio needed to trigger the state change
 * @param E An event object
 * @param S Actual posted state
 * @return The event state
 */
boolean_t Event_check_state(Event_T E, State_Type S) {
        int        count = 0;
        State_Type state = (S == State_Succeeded || S == State_ChangedNot) ? State_Succeeded : State_Failed; /* translate to 0/1 class */
        Action_T   action;
        Service_T  service;
        long long  flag;

        ASSERT(E);

        if (! (service = Event_get_source(E)))
                return true;

        /* Only true failed/changed state condition can change the initial state */
        if (! state && E->state == State_Init && ! (service->error & E->id))
                return false;

        action = ! state ? E->action->succeeded : E->action->failed;

        /* Compare as many bits as cycles able to trigger the action */
        for (int i = 0; i < action->cycles; i++) {
                /* Check the state of the particular cycle given by the bit position */
                flag = (E->state_map >> i) & 0x1;

                /* Count occurences of the posted state */
                if (flag == state)
                        count++;
        }

        /* the internal instance and action events are handled as changed any time since we need to deliver alert whenever it occurs */
        if (E->id == Event_Instance || E->id == Event_Action || (count >= action->count && (S != E->state || S == State_Changed))) {
                memset(&(E->state_map), state, sizeof(E->state_map)); // Restart state map on state change, so we'll not flicker on multiple-failures condition (next state change requires full number of cycles to pass)
                return true;
        }

        return false;
}


/**
 * Get the Event type
 * @param E An event object
 * @return The Event type
 */
long Event_get_id(Event_T E) {
        ASSERT(E);
        return E->id;
}


/**
 * Get the optionally Event message describing why the event was
 * fired.
 * @param E An event object
 * @return The Event message. May be NULL
 */
const char *Event_get_message(Event_T E) {
        ASSERT(E);
        return E->message;
}


/**
 * Get a textual description of actual event type.
 * @param E An event object
 * @return A string describing the event type in clear text. If the
 * event type is not found NULL is returned.
 */
const char *Event_get_description(Event_T E) {
        EventTable_T *et = Event_Table;

        ASSERT(E);

        while ((*et).id) {
                if (E->id == (*et).id) {
                        switch (E->state) {
                                case State_Succeeded:
                                        return (*et).description_succeeded;
                                case State_Failed:
                                        return (*et).description_failed;
                                case State_Init:
                                        return (*et).description_failed;
                                case State_Changed:
                                        return (*et).description_changed;
                                case State_ChangedNot:
                                        return (*et).description_changednot;
                                default:
                                        break;
                        }
                }
                et++;
        }

        return NULL;
}


/**
 * Get an event action id.
 * @param E An event object
 * @return An action id
 */
Action_Type Event_get_action(Event_T E) {
        ASSERT(E);

        Action_T A = NULL;
        switch (E->state) {
                case State_Succeeded:
                case State_ChangedNot:
                        A = E->action->succeeded;
                        break;
                case State_Failed:
                case State_Changed:
                case State_Init:
                        A = E->action->failed;
                        break;
                default:
                        LogError("Invalid event state: %d\n", E->state);
                        return Action_Ignored;
        }
        if (! A)
                return Action_Ignored;
        /* In the case of passive mode we replace the description of start, stop or restart action for alert action, because these actions are passive in this mode */
        return (E->mode == Monitor_Passive && ((A->id == Action_Start) || (A->id == Action_Stop) || (A->id == Action_Restart))) ? Action_Alert : A->id;
}


/**
 * Get a textual description of actual event action. For instance if the
 * event type is possitive Event_Nonexist, the textual description of
 * failed state related action is "restart". Likewise if the event type is
 * negative Event_Checksumthe textual description of recovery related action
 * is "alert" and so on.
 * @param E An event object
 * @return A string describing the event type in clear text. If the
 * event type is not found NULL is returned.
 */
const char *Event_get_action_description(Event_T E) {
        ASSERT(E);
        return actionnames[Event_get_action(E)];
}


/**
 * Reprocess the partially handled event queue
 */
void Event_queue_process() {
        /* return in the case that the eventqueue is not enabled or empty */
        if (! Run.eventlist_dir || (! (Run.flags & Run_HandlerInit) && ! Run.handler_queue[Handler_Alert] && ! Run.handler_queue[Handler_Mmonit]))
                return;

        DIR *dir = opendir(Run.eventlist_dir);
        if (! dir) {
                if (errno != ENOENT)
                        LogError("Cannot open the directory %s -- %s\n", Run.eventlist_dir, STRERROR);
                return;
        }

        struct dirent *de = readdir(dir);
        if (de)
                DEBUG("Processing postponed events queue\n");

        Action_T a;
        NEW(a);

        EventAction_T ea;
        NEW(ea);

        while (de) {
                int handlers_passed = 0;

                /* In the case that all handlers failed, skip the further processing in this cycle. Alert handler is currently defined anytime (either explicitly or localhost by default) */
                if ( (Run.mmonits && FLAG(Run.handler_flag, Handler_Mmonit) && FLAG(Run.handler_flag, Handler_Alert)) || FLAG(Run.handler_flag, Handler_Alert))
                        break;

                char file_name[PATH_MAX];
                snprintf(file_name, sizeof(file_name), "%s/%s", Run.eventlist_dir, de->d_name);

                if (File_isFile(file_name)) {
                        LogInfo("Processing queued event %s\n", file_name);

                        FILE *file = fopen(file_name, "r");
                        if (! file) {
                                LogError("Queued event processing failed - cannot open the file %s -- %s\n", file_name, STRERROR);
                                goto error1;
                        }

                        size_t size;

                        /* read event structure version */
                        int *version = file_readQueue(file, &size);
                        if (! version) {
                                LogError("skipping queued event %s - unknown data format\n", file_name);
                                goto error2;
                        }
                        if (size != sizeof(int)) {
                                LogError("Aborting queued event %s - invalid size %lu\n", file_name, (unsigned long)size);
                                goto error3;
                        }
                        if (*version != EVENT_VERSION) {
                                LogError("Aborting queued event %s - incompatible data format version %d\n", file_name, *version);
                                goto error3;
                        }

                        /* read event structure */
                        Event_T e = file_readQueue(file, &size);
                        if (! e)
                                goto error3;
                        if (size != sizeof(*e))
                                goto error4;

                        /* read source */
                        if (! (e->source = file_readQueue(file, &size)))
                                goto error4;

                        /* read message */
                        if (! (e->message = file_readQueue(file, &size)))
                                goto error5;

                        /* read event action */
                        Action_Type *action = file_readQueue(file, &size);
                        if (! action)
                                goto error6;
                        if (size != sizeof(Action_Type))
                                goto error7;
                        a->id = *action;
                        switch (e->state) {
                                case State_Succeeded:
                                case State_ChangedNot:
                                        ea->succeeded = a;
                                        break;
                                case State_Failed:
                                case State_Changed:
                                case State_Init:
                                        ea->failed = a;
                                        break;
                                default:
                                        LogError("Aborting queue event %s -- invalid state: %d\n", file_name, e->state);
                                        goto error7;
                        }
                        e->action = ea;

                        /* Retry all remaining handlers */

                        /* alert */
                        if (e->flag & Handler_Alert) {
                                if (Run.flags & Run_HandlerInit)
                                        Run.handler_queue[Handler_Alert]++;
                                if ((Run.handler_flag & Handler_Alert) != Handler_Alert) {
                                        if ( handle_alert(e) != Handler_Alert ) {
                                                e->flag &= ~Handler_Alert;
                                                Run.handler_queue[Handler_Alert]--;
                                                handlers_passed++;
                                        } else {
                                                LogError("Alert handler failed, retry scheduled for next cycle\n");
                                                Run.handler_flag |= Handler_Alert;
                                        }
                                }
                        }

                        /* mmonit */
                        if (e->flag & Handler_Mmonit) {
                                if (Run.flags & Run_HandlerInit)
                                        Run.handler_queue[Handler_Mmonit]++;
                                if ((Run.handler_flag & Handler_Mmonit) != Handler_Mmonit) {
                                        if ( handle_mmonit(e) != Handler_Mmonit ) {
                                                e->flag &= ~Handler_Mmonit;
                                                Run.handler_queue[Handler_Mmonit]--;
                                                handlers_passed++;
                                        } else {
                                                LogError("M/Monit handler failed, retry scheduled for next cycle\n");
                                                Run.handler_flag |= Handler_Mmonit;
                                        }
                                }
                        }

                        /* If no error persists, remove it from the queue */
                        if (e->flag == Handler_Succeeded) {
                                DEBUG("Removing queued event %s\n", file_name);
                                if (unlink(file_name) < 0)
                                        LogError("Failed to remove queued event file '%s' -- %s\n", file_name, STRERROR);
                        } else if (handlers_passed > 0) {
                                DEBUG("Updating queued event %s (some handlers passed)\n", file_name);
                                Event_queue_update(e, file_name);
                        }

                error7:
                        FREE(action);
                error6:
                        FREE(e->message);
                error5:
                        FREE(e->source);
                error4:
                        FREE(e);
                error3:
                        FREE(version);
                error2:
                        fclose(file);
                }
        error1:
                de = readdir(dir);
        }
        Run.flags &= ~Run_HandlerInit;
        closedir(dir);
        FREE(a);
        FREE(ea);
        return;
}


/* ----------------------------------------------------------------- Private */


/*
 * Handle the event
 * @param E An event
 */
static void handle_event(Service_T S, Event_T E) {
        ASSERT(E);
        ASSERT(E->action);
        ASSERT(E->action->failed);
        ASSERT(E->action->succeeded);

        /* We will handle only first succeeded event, recurrent succeeded events
         * or insufficient succeeded events during failed service state are
         * ignored. Failed events are handled each time. */
        if (! E->state_changed && (E->state == State_Succeeded || E->state == State_ChangedNot || ((E->state_map & 0x1) ^ 0x1))) {
                DEBUG("'%s' %s\n", S->name, E->message);
                return;
        }

        if (E->message) {
                /* In the case that the service state is initializing yet and error
                 * occured, log it and exit. Succeeded events in init state are not
                 * logged. Instance and action events are logged always with priority
                 * info. */
                if (E->state != State_Init || E->state_map & 0x1) {
                        if (E->state == State_Succeeded || E->state == State_ChangedNot || E->id == Event_Instance || E->id == Event_Action)
                                LogInfo("'%s' %s\n", S->name, E->message);
                        else
                                LogError("'%s' %s\n", S->name, E->message);
                }
                if (E->state == State_Init)
                        return;
        }

        if (E->state == State_Failed || E->state == State_Changed) {
                if (E->id != Event_Instance && E->id != Event_Action) { // We are not interested in setting error flag for instance and action events
                        S->error |= E->id;
                        /* The error hint provides second dimension for error bitmap and differentiates between failed/changed event states (failed=0, chaged=1) */
                        if (E->state == State_Changed)
                                S->error_hint |= E->id;
                        else
                                S->error_hint &= ~E->id;
                }
                handle_action(E, E->action->failed);
        } else {
                S->error &= ~E->id;
                handle_action(E, E->action->succeeded);
        }

        /* Possible event state change was handled so we will reset the flag. */
        E->state_changed = false;
}


static void handle_action(Event_T E, Action_T A) {
        Service_T s;

        ASSERT(E);
        ASSERT(A);

        E->flag = Handler_Succeeded;

        if (A->id == Action_Ignored)
                return;

        /* Alert and mmonit event notification are common actions */
        E->flag |= handle_mmonit(E);
        E->flag |= handle_alert(E);

        /* In the case that some subhandler failed, enqueue the event for
         * partial reprocessing */
        if (E->flag != Handler_Succeeded) {
                if (Run.eventlist_dir)
                        Event_queue_add(E);
                else
                        LogError("Aborting event\n");
        }

        if (! (s = Event_get_source(E))) {
                LogError("Event action handling aborted\n");
                return;
        }

        /* Action event is handled already. For Instance events
         * we don't want actions like stop to be executed
         * to prevent the disabling of system service monitoring */
        if (A->id == Action_Alert || E->id == Event_Instance) {
                return;
        } else if (A->id == Action_Exec) {
                LogInfo("'%s' exec: %s\n", s->name, A->exec->arg[0]);
                spawn(s, A->exec, E);
                return;
        } else {
                if (s->actionratelist && (A->id == Action_Start || A->id == Action_Restart))
                        s->nstart++;

                if (s->mode == Monitor_Passive && (A->id == Action_Start || A->id == Action_Stop  || A->id == Action_Restart))
                        return;

                control_service(s->name, A->id);
        }
}


/**
 * Add the partialy handled event to the global queue
 * @param E An event object
 */
static void Event_queue_add(Event_T E) {
        ASSERT(E);
        ASSERT(E->flag != Handler_Succeeded);

        if (! file_checkQueueDirectory(Run.eventlist_dir)) {
                LogError("Aborting event - cannot access the directory %s\n", Run.eventlist_dir);
                return;
        }

        if (! file_checkQueueLimit(Run.eventlist_dir, Run.eventlist_slots)) {
                LogError("Aborting event - queue over quota\n");
                return;
        }

        /* compose the file name of actual timestamp and service name */
        char file_name[PATH_MAX];
        snprintf(file_name, PATH_MAX, "%s/%lld_%lx", Run.eventlist_dir, (long long)Time_now(), (long unsigned)E->source);

        LogInfo("Adding event to the queue file %s for later delivery\n", file_name);

        FILE *file = fopen(file_name, "w");
        if (! file) {
                LogError("Aborting event - cannot open the event file %s -- %s\n", file_name, STRERROR);
                return;
        }

        boolean_t  rv;

        /* write event structure version */
        int version = EVENT_VERSION;
        if (! (rv = file_writeQueue(file, &version, sizeof(int))))
                goto error;

        /* write event structure */
        if (! (rv = file_writeQueue(file, E, sizeof(*E))))
                goto error;

        /* write source */
        if (! (rv = file_writeQueue(file, E->source, E->source ? strlen(E->source) + 1 : 0)))
                goto error;

        /* write message */
        if (! (rv = file_writeQueue(file, E->message, E->message ? strlen(E->message) + 1 : 0)))
                goto error;

        /* write event action */
        Action_Type action = Event_get_action(E);
        if (! (rv = file_writeQueue(file, &action, sizeof(Action_Type))))
                goto error;

error:
        fclose(file);
        if (! rv) {
                LogError("Aborting event - unable to save event information to %s\n",  file_name);
                if (unlink(file_name) < 0)
                        LogError("Failed to remove event file '%s' -- %s\n", file_name, STRERROR);
        } else {
                if (! (Run.flags & Run_HandlerInit) && E->flag & Handler_Alert)
                        Run.handler_queue[Handler_Alert]++;
                if (! (Run.flags & Run_HandlerInit) && E->flag & Handler_Mmonit)
                        Run.handler_queue[Handler_Mmonit]++;
        }

        return;
}


/**
 * Update the partialy handled event in the global queue
 * @param E An event object
 * @param file_name File name
 */
static void Event_queue_update(Event_T E, const char *file_name) {
        int version = EVENT_VERSION;
        Action_Type action = Event_get_action(E);
        boolean_t rv;

        ASSERT(E);
        ASSERT(E->flag != Handler_Succeeded);

        if (! file_checkQueueDirectory(Run.eventlist_dir)) {
                LogError("Aborting event - cannot access the directory %s\n", Run.eventlist_dir);
                return;
        }

        DEBUG("Updating event in the queue file %s for later delivery\n", file_name);

        FILE *file = fopen(file_name, "w");
        if (! file) {
                LogError("Aborting event - cannot open the event file %s -- %s\n", file_name, STRERROR);
                return;
        }

        /* write event structure version */
        if (! (rv = file_writeQueue(file, &version, sizeof(int))))
                goto error;

        /* write event structure */
        if (! (rv = file_writeQueue(file, E, sizeof(*E))))
                goto error;

        /* write source */
        if (! (rv = file_writeQueue(file, E->source, E->source ? strlen(E->source) + 1 : 0)))
                goto error;

        /* write message */
        if (! (rv = file_writeQueue(file, E->message, E->message ? strlen(E->message) + 1 : 0)))
                goto error;

        /* write event action */
        if (! (rv = file_writeQueue(file, &action, sizeof(Action_Type))))
                goto error;

error:
        fclose(file);
        if (! rv) {
                LogError("Aborting event - unable to update event information to %s\n", file_name);
                if (unlink(file_name) < 0)
                        LogError("Failed to remove event file '%s' -- %s\n", file_name, STRERROR);
        }

        return;
}

