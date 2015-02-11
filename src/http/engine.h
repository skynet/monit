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


#ifndef ENGINE_H
#define ENGINE_H


/**
 * Start the HTTPD server
 */
void Engine_start();


/**
 * Stop the HTTPD server.
 */
void Engine_stop();


/**
 * Cleanup the HTTPD server resources (remove unix socket).
 */
void Engine_cleanup();


/**
 * Add hosts allowed to connect to this server.
 * @param pattern A hostname (A-Record) or IP address to be added to the hosts allow list
 * @return false if the given host does not resolve, otherwise true
 */
boolean_t Engine_addHostAllow(char *pattern);


/**
 * Add network allowed to connect to this server.
 * @param pattern A network identifier in IP/mask format to be added
 * to the hosts allow list
 * @return false if no correct network identifier is provided,
 * otherwise true
 */
boolean_t Engine_addNetAllow(char *pattern);


/**
 * Are any hosts present in the host allow list?
 * @return true if the host allow list is non-empty, otherwise false
 */
boolean_t Engine_hasHostsAllow();


/**
 * Free the host allow list
 */
void Engine_destroyHostsAllow();


#endif
