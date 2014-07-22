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

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#include "monit.h"
#include "event.h"
#include "net.h"
#include "alert.h"

// libmonit
#include "system/Time.h"
#include "util/Str.h"


/**
 *  Implementation of the alert module
 *
 *  @file
 */


/* -------------------------------------------------------------- Prototypes */


static void copy_mail(Mail_T, Mail_T);
static void escape(Mail_T);
static void substitute(Mail_T, Event_T);


/* ------------------------------------------------------------------ Public */


/**
 * Notify registred users about the event
 * @param E An Event object
 * @return If failed, return HANDLER_ALERT flag or HANDLER_SUCCEEDED if succeeded
 */
int handle_alert(Event_T E) {
  Service_T s;
  int rv = HANDLER_SUCCEEDED;

  ASSERT(E);

  s = Event_get_source(E);
  if(!s) {
    LogError("Aborting alert\n");
    return rv;
  }

  if(s->maillist || Run.maillist) {
    Mail_T m;
    Mail_T n;
    Mail_T list = NULL;
    /*
     * Build a mail-list with local recipients that has registered interest
     * for this event.
     */
    for(m = s->maillist; m; m = m->next) {

      if(
        /* particular event notification type is allowed for given recipient */
        IS_EVENT_SET(m->events, Event_get_id(E)) &&
        (
          /* state change notification is sent always */
          E->state_changed       ||
          /* in the case that the state is failed for more cycles we check
           * whether we should send the reminder */
          (E->state && m->reminder && E->count % m->reminder == 0)
        )
      )
      {
        Mail_T tmp = NULL;

        NEW(tmp);
        copy_mail(tmp, m);
        substitute(tmp, E);
        escape(tmp);
        tmp->next = list;
        list = tmp;

        DEBUG("%s notification is sent to %s\n", Event_get_description(E), m->to);

      }

    }

    /*
     * Build a mail-list with global recipients that has registered interest
     * for this event. Recipients which are defined in the service localy
     * overrides the same recipient events which are registered globaly.
     */
    for(m = Run.maillist; m; m = m->next) {
      int skip = FALSE;

      for(n = s->maillist; n; n = n->next) {
        if(IS(m->to, n->to)) {
          skip = TRUE;
          break;
        }
      }

      if(
        /* the local service alert definition has not overrided the global one */
        !skip &&
        /* particular event notification type is allowed for given recipient */
        IS_EVENT_SET(m->events, Event_get_id(E)) &&
        (
          /* state change notification is sent always */
          E->state_changed       ||
          /* in the case that the state is failed for more cycles we check
           * whether we should send the reminder */
          (E->state && m->reminder && E->count % m->reminder == 0)
        )
      )
      {

        Mail_T tmp = NULL;

        NEW(tmp);
        copy_mail(tmp, m);
        substitute(tmp, E);
        escape(tmp);
        tmp->next = list;
        list = tmp;

        DEBUG("%s notification is sent to %s\n", Event_get_description(E), m->to);

      }

    }

    if(list) {

      if(sendmail(list))
        rv = HANDLER_ALERT;
      gc_mail_list(&list);

    }

  }

  return rv;

}


static void substitute(Mail_T m, Event_T e) {
  char timestamp[STRLEN];

  ASSERT(m && e);

  Util_replaceString(&m->from,    "$HOST", Run.system->name);
  Util_replaceString(&m->subject, "$HOST", Run.system->name);
  Util_replaceString(&m->message, "$HOST", Run.system->name);

  Time_string(e->collected.tv_sec, timestamp);
  Util_replaceString(&m->subject, "$DATE", timestamp);
  Util_replaceString(&m->message, "$DATE", timestamp);

  Util_replaceString(&m->subject, "$SERVICE", Event_get_source_name(e));
  Util_replaceString(&m->message, "$SERVICE", Event_get_source_name(e));

  Util_replaceString(&m->subject, "$EVENT", Event_get_description(e));
  Util_replaceString(&m->message, "$EVENT", Event_get_description(e));

  Util_replaceString(&m->subject, "$DESCRIPTION", NVLSTR(Event_get_message(e)));
  Util_replaceString(&m->message, "$DESCRIPTION", NVLSTR(Event_get_message(e)));

  Util_replaceString(&m->subject, "$ACTION", Event_get_action_description(e));
  Util_replaceString(&m->message, "$ACTION", Event_get_action_description(e));
}


static void copy_mail(Mail_T n, Mail_T o) {
  ASSERT(n && o);

  n->to = Str_dup(o->to);
  n->from=
      o->from?
      Str_dup(o->from):
      Run.MailFormat.from?
      Str_dup(Run.MailFormat.from):
      Str_dup(ALERT_FROM);
  n->replyto =
      o->replyto?
      Str_dup(o->replyto):
      Run.MailFormat.replyto?
      Str_dup(Run.MailFormat.replyto):
      NULL;
  n->subject=
      o->subject?
      Str_dup(o->subject):
      Run.MailFormat.subject?
      Str_dup(Run.MailFormat.subject):
      Str_dup(ALERT_SUBJECT);
  n->message=
      o->message?
      Str_dup(o->message):
      Run.MailFormat.message?
      Str_dup(Run.MailFormat.message):
      Str_dup(ALERT_MESSAGE);
}


static void escape(Mail_T m) {
  // replace bare linefeed
  Util_replaceString(&m->message, "\r\n", "\n");
  Util_replaceString(&m->message, "\n", "\r\n");
  // escape ^.
  Util_replaceString(&m->message, "\n.", "\n..");
  // drop any CR|LF from the subject
  Str_chomp(m->subject);
}
