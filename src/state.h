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


#ifndef MONIT_STATE_H
#define MONIT_STATE_H


/**
 * Management of the persistent service properties.
 *
 * If Monit runs in daemon mode, it saves the persistent properties of every
 * service to the state file at the end of every poll cycle. When Monit is
 * restarted or reloaded, it restores the state of the services from this file.
 *
 * The location of the state file defaults to ~/.monit.state and can be
 * overriden on the command line or using the "set statefile" statement in the
 * configuration file.
 *
 *  @file
 */


/**
 * Open the state file
 * @return true if succeeded, otherwise false
 */
boolean_t State_open();


/**
 * Close the state file
 */
void State_close();


/**
 * Save service state information to the state file
 */
void State_save();


/**
 * Update the current service list with data from the state file. We
 * do change only services found in *both* the monitrc file and in
 * the state file. The algorithm:
 *
 * Assume the control file was changed and a new service (B) was added
 * so the monitrc file now contains the services: A B and C. The
 * running monit daemon only knows the services A and C. Upon restart
 * after a crash the monit daemon first read the monitrc file and
 * creates the service list structure with A B and C. We then read the
 * state file and update the service A and C since they are found in
 * the state file, B is not found in this file and therefore not
 * changed.
 *
 * The same strategy is used if a service was removed, e.g. if the
 * service A was removed from monitrc; when reading the state file,
 * service A is not found in the current service list (the list is
 * always generated from monitrc) and therefore A is simply discarded.
 */
void State_update();


#endif
