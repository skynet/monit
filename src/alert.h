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


#ifndef MONIT_ALERT_H
#define MONIT_ALERT_H

#include "event.h"


/** Default mail from string */
#define ALERT_FROM    "monit@$HOST"

/** Default mail subject */
#define ALERT_SUBJECT "monit alert --  $EVENT $SERVICE"

/** Default mail message */
#define ALERT_MESSAGE "$EVENT Service $SERVICE \r\n"\
                      "\r\n"\
                      "\tDate:        $DATE\r\n"\
                      "\tAction:      $ACTION\r\n"\
                      "\tHost:        $HOST\r\n"\
                      "\tDescription: $DESCRIPTION\r\n"\
                      "\r\n"\
                      "Your faithful employee,\r\n"\
                      "Monit\r\n"


/**
 *  This module is used for event notifications. Users may register
 *  interest for certain events in the monit control file. When an
 *  event occurs this module is called from the event processing
 *  machinery to notify users who have asked to be alerted for
 *  particular events.
 *
 *  @file
 */


/**
 * Notify registred users about the event
 * @param E An Event object
 * @return If failed, return Handler_Alert flag or Handler_Succeeded flag if succeeded
 */
Handler_Type handle_alert(Event_T E);


#endif
