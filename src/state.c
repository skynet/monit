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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif



#include "monit.h"
#include "state.h"

// libmonit
#include "exceptions/IOException.h"


/**
 * The list of persistent properties:
 *
 *    1.) service name + service type
 *        Monit configuration may change, so the state restore needs to ignore
 *        the removed services or services which type doesn't match (the
 *        service name was reused for different check). The current service
 *        runtime is thus paired with the saved service state by name and type.
 *
 *    2.) monitoring state
 *        Keep the monitoring enabled or disabled on Monit restart. Useful for
 *        example when Monit is running in active/passive cluster, so the
 *        service monitoring mode doesn't reset when Monit needs to be reloaded
 *        and the service won't enter unwanted passive/passive or active/active
 *        state on multiple hosts. Another example is service which timed out
 *        due to excessive errors or the monitoring was intentionally disabled
 *        by admin for maintenance - do not re-enable monitoring on Monit reload.
 *
 *    3.) service restart counters
 *
 *    4.) inode number and read position for the file check
 *        Allows to skip the content match test for the content which was checked
 *        already to suppress duplicate events.
 *
 * Data is stored in binary form in the statefile using the following format:
 *    <MAGIC><VERSION>{<SERVICE_STATE>}+
 *
 * When the persistent field needs to be added, update the State_Version along
 * with State_update() and State_save(). The version allows to recognize the
 * service state structure and file format.
 *
 * The backward compatibility of monitoring state restore is very important if
 * Monit runs in cluster => keep previous formats compatibility.
 *
 * @file
 */


/* ------------------------------------------------------------- Definitions */


/* Extended format version */
typedef enum {
        StateVersion0 = 0,
        StateVersion1
} State_Version;


/* Format version 0 (Monit <= 5.3) */
typedef struct mystate0 {
        char               name[STRLEN];
        int                mode;                // obsolete since Monit 5.1
        int                nstart;
        int                ncycle;
        int                monitor;
        unsigned long long error;               // obsolete since Monit 5.0
} State0_T;


/* Extended format version 1 */
typedef struct mystate1 {
        char               name[STRLEN];
        int                type;
        int                monitor;
        int                nstart;
        int                ncycle;
        union {
                struct {
                        unsigned long long st_ino;
                        unsigned long long readpos;
                } file;
        } priv;
} State1_T;


static int file = -1;


/* ----------------------------------------------------------------- Private */


static void update_v0(int services) {
        for (int i = 0; i < services; i++) {
                State0_T state;
                if (read(file, &state, sizeof(state)) != sizeof(state))
                        THROW(IOException, "Unable to read service state");
                Service_T service;
                if ((service = Util_getService(state.name))) {
                        service->nstart = state.nstart;
                        service->ncycle = state.ncycle;
                        if (state.monitor == MONITOR_NOT)
                                service->monitor = state.monitor;
                        else if (service->monitor == MONITOR_NOT)
                                service->monitor = MONITOR_INIT;
                }
        }
}


static void update_v1() {
        State1_T state;
        while (read(file, &state, sizeof(state)) == sizeof(state)) {
                Service_T service;
                if ((service = Util_getService(state.name)) && service->type == state.type) {
                        service->nstart = state.nstart;
                        service->ncycle = state.ncycle;
                        if (state.monitor == MONITOR_NOT)
                                service->monitor = state.monitor;
                        else if (service->monitor == MONITOR_NOT)
                                service->monitor = MONITOR_INIT;
                        if (service->type == TYPE_FILE) {
                                service->inf->priv.file.st_ino = state.priv.file.st_ino;
                                service->inf->priv.file.readpos = state.priv.file.readpos;
                        }
                }
        }
}


/* ------------------------------------------------------------------ Public */


int State_open() {
        State_close();
        if ((file = open(Run.statefile, O_RDWR | O_CREAT, 0600)) == -1) {
                LogError("Cannot open for write -- %s\n", STRERROR);
                return FALSE;
        }
        atexit(State_close);
        return TRUE;
}


void State_close() {
        if (file != -1) {
                if (close(file) == -1)
                        LogError("State file '%s': close error -- %s\n", Run.statefile, STRERROR);
                else
                        file = -1;
        }
}


void State_save() {
        TRY
        {
                if (ftruncate(file, 0L) == -1)
                        THROW(IOException, "Unable to truncate");
                if (lseek(file, 0L, SEEK_SET) == -1)
                        THROW(IOException, "Unable to seek");
                int magic = 0;
                if (write(file, &magic, sizeof(magic)) != sizeof(magic))
                        THROW(IOException, "Unable to write magic");
                // Save always using the latest format version
                int version = StateVersion1;
                if (write(file, &version, sizeof(version)) != sizeof(version))
                        THROW(IOException, "Unable to write format version");
                for (Service_T service = servicelist; service; service = service->next) {
                        State1_T state;
                        memset(&state, 0, sizeof(state));
                        snprintf(state.name, sizeof(state.name), "%s", service->name);
                        state.type = service->type;
                        state.monitor = service->monitor & ~MONITOR_WAITING;
                        state.nstart = service->nstart;
                        state.ncycle = service->ncycle;
                        if (service->type == TYPE_FILE) {
                                state.priv.file.st_ino = service->inf->priv.file.st_ino;
                                state.priv.file.readpos = service->inf->priv.file.readpos;
                        }
                        if (write(file, &state, sizeof(state)) != sizeof(state))
                                THROW(IOException, "Unable to write service state");
                }
                if (fsync(file))
                        THROW(IOException, "Unable to sync -- %s", STRERROR);
        }
        ELSE
        {
                LogError("State file '%s': %s\n", Run.statefile, Exception_frame.message);
        }
        END_TRY;
}


void State_update() {
        /* Ignore empty state file */
        if ((lseek(file, 0L, SEEK_END) == 0))
             return;
        TRY
        {
                if (lseek(file, 0L, SEEK_SET) == -1)
                        THROW(IOException, "Unable to seek");
                int magic;
                if (read(file, &magic, sizeof(magic)) != sizeof(magic))
                        THROW(IOException, "Unable to read magic");
                if (magic > 0) {
                        // The statefile format of Monit <= 5.3, the magic is number of services, followed by State0_T structures
                        update_v0(magic);
                } else {
                        // The extended statefile format (Monit >= 5.4)
                        int version;
                        if (read(file, &version, sizeof(version)) != sizeof(version))
                                THROW(IOException, "Unable to read version");
                        // Currently the extended format has only one version, additional versions can be added here
                        if (version == StateVersion1)
                                update_v1();
                        else
                                LogWarning("State file '%s': incompatible version %d\n", Run.statefile, version);
                }
        }
        ELSE
        {
                LogError("State file '%s': %s\n", Run.statefile, Exception_frame.message);
        }
        END_TRY;
}

