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


#ifdef HAVE_OPENSSL


#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "monit.h"
#include "Ssl.h"
#include "SslServer.h"

// libmonit
#include "io/File.h"
#include "system/Net.h"
#include "exceptions/AssertException.h"


/**
 *  SSL implementation
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


/**
 * Number of random bytes to obtain
 */
#define RANDOM_BYTES 1024


/**
 * The PRIMARY random device selected for seeding the PRNG. We use a non-blocking pseudo random device, to generate pseudo entropy.
 */
#define URANDOM_DEVICE "/dev/urandom"


/**
 * If a non-blocking device is not found on the system a blocking entropy producer is tried instead.
 */
#define RANDOM_DEVICE "/dev/random"


#define SSLERROR ERR_error_string(ERR_get_error(),NULL)


#define T Ssl_T
struct T {
        boolean_t accepted;
        Ssl_Version version;
        int socket;
        SSL *handler;
        SSL_CTX *ctx;
        char *clientpemfile;
};


struct SslServer_T {
        int socket;
        SSL_CTX *ctx;
        char *pemfile;
        char *clientpemfile;
};


static Mutex_T *instanceMutexTable;


/* ----------------------------------------------------------------- Private */


static unsigned long _threadID() {
        return (unsigned long)Thread_self();
}


static void _mutexLock(int mode, int n, const char *file, int line) {
        if (mode & CRYPTO_LOCK)
                Mutex_lock(instanceMutexTable[n]);
        else
                Mutex_unlock(instanceMutexTable[n]);
}


static int _verifyCertificates(int preverify_ok, X509_STORE_CTX *ctx) {
        char subject[STRLEN];
        X509_NAME_oneline(X509_get_subject_name(ctx->current_cert), subject, STRLEN - 1);
        if (! preverify_ok) {
                if (ctx->error != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
                        if (ctx->error != X509_V_ERR_INVALID_PURPOSE) {
                                LogError("SSL: invalid certificate [%i]\n", ctx->error);
                                return 0;
                        }
                } else if (! (Run.httpd.flags & Httpd_AllowSelfSignedCertificates)) {
                        LogError("SSL: self-signed certificate not allowed [%i]\n", ctx->error);
                        return 0;
                } else {
                        ctx->error = 0;
                }
        }
        X509_OBJECT found_cert;
        if (ctx->error_depth == 0 && X509_STORE_get_by_subject(ctx, X509_LU_X509, X509_get_subject_name(ctx->current_cert), &found_cert) != 1) {
                LogError("SSL: no matching certificate found -- %s\n", SSLERROR);
                return 0;
        }
        return 1;
}


static boolean_t _setServerNameIdentification(T C, const char *hostname) {
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        struct sockaddr_storage addr;
        // If the name is set and we use TLS protocol, enable the SNI extension (provided the hostname value is not an IP address)
        if (hostname && C->version != SSL_V2 && C->version != SSL_V3 && ! inet_pton(AF_INET, hostname, &(((struct sockaddr_in *)&addr)->sin_addr)) &&
#ifdef HAVE_IPV6
                ! inet_pton(AF_INET6, hostname, &(((struct sockaddr_in6 *)&addr)->sin6_addr)) &&
#endif
                ! SSL_set_tlsext_host_name(C->handler, hostname)) {
                        LogError("SSL: unable to set the SNI extension to %s\n", hostname);
                        return false;
                }
#endif
        return true;
}


/* ------------------------------------------------------------------ Public */


void Ssl_start() {
        SSL_library_init();
        SSL_load_error_strings();
        if (File_exist(URANDOM_DEVICE))
                RAND_load_file(URANDOM_DEVICE, RANDOM_BYTES);
        else if (File_exist(RANDOM_DEVICE))
                RAND_load_file(RANDOM_DEVICE, RANDOM_BYTES);
        else
                THROW(AssertException, "SSL: cannot find %s nor %s on the system", URANDOM_DEVICE, RANDOM_DEVICE);
        int locks = CRYPTO_num_locks();
        instanceMutexTable = CALLOC(locks, sizeof(Mutex_T));
        for (int i = 0; i < locks; i++)
                Mutex_init(instanceMutexTable[i]);
        CRYPTO_set_id_callback(_threadID);
        CRYPTO_set_locking_callback(_mutexLock);
}


void Ssl_stop() {
        CRYPTO_set_id_callback(NULL);
        CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < CRYPTO_num_locks(); i++)
                Mutex_destroy(instanceMutexTable[i]);
        FREE(instanceMutexTable);
        RAND_cleanup();
        ERR_free_strings();
        Ssl_threadCleanup();
}


void Ssl_threadCleanup() {
        ERR_remove_state(0);
}


void Ssl_setFipsMode(boolean_t enabled) {
#ifdef OPENSSL_FIPS
        if (enabled && ! FIPS_mode() && ! FIPS_mode_set(1))
                THROW(AssertException, "SSL: cannot enter FIPS mode -- %s", SSLERROR);
        else if (! enabled && FIPS_mode() && ! FIPS_mode_set(0))
                THROW(AssertException, "SSL: cannot exit FIPS mode -- %s", SSLERROR);
#endif
}


T Ssl_new(char *clientpemfile, Ssl_Version version) {
        T C;
        NEW(C);
        C->version = version;
        if (clientpemfile)
                C->clientpemfile = Str_dup(clientpemfile);
        const SSL_METHOD *method;
        switch (version) {
                case SSL_V2:
#ifdef OPENSSL_NO_SSL2
                        LogError("SSL: SSLv2 not supported\n");
                        goto sslerror;
#else
                        if (Run.fipsEnabled) {
                                LogError("SSL: SSLv2 is not allowed in FIPS mode -- use TLS\n");
                                goto sslerror;
                        }
                        method = SSLv2_client_method();
#endif
                        break;
                case SSL_V3:
                        if (Run.fipsEnabled) {
                                LogError("SSL: SSLv3 is not allowed in FIPS mode -- use TLS\n");
                                goto sslerror;
                        }
                        method = SSLv3_client_method();
                        break;
                case SSL_TLSV1:
                        method = TLSv1_client_method();
                        break;
#ifdef HAVE_TLSV1_1
                case SSL_TLSV11:
                        method = TLSv1_1_client_method();
                        break;
#endif
#ifdef HAVE_TLSV1_2
                case SSL_TLSV12:
                        method = TLSv1_2_client_method();
                        break;
#endif
                case SSL_Auto:
                default:
                        method = SSLv23_client_method();
                        break;
        }
        if (! method) {
                LogError("SSL: client method initialization failed -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (! (C->ctx = SSL_CTX_new(method))) {
                LogError("SSL: client context initialization failed -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (version == SSL_Auto)
                SSL_CTX_set_options(C->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
#ifdef SSL_OP_NO_COMPRESSION
        SSL_CTX_set_options(C->ctx, SSL_OP_NO_COMPRESSION);
#endif
        if (SSL_CTX_set_cipher_list(C->ctx, CIPHER_LIST) != 1) {
                LogError("SSL: client cipher list [%s] error -- no valid ciphers\n", CIPHER_LIST);
                goto sslerror;
        }
        if (! (C->handler = SSL_new(C->ctx))) {
                LogError("SSL: cannot create client handler -- %s\n", SSLERROR);
                goto sslerror;
        }
        SSL_set_mode(C->handler, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        if (C->clientpemfile) {
                if (SSL_CTX_use_certificate_chain_file(C->ctx, C->clientpemfile) != 1) {
                        LogError("SSL: client certificate chain loading failed -- %s\n", SSLERROR);
                        goto sslerror;
                }
                if (SSL_CTX_use_PrivateKey_file(C->ctx, C->clientpemfile, SSL_FILETYPE_PEM) != 1) {
                        LogError("SSL: client private key loading failed -- %s\n", SSLERROR);
                        goto sslerror;
                }
                if (SSL_CTX_check_private_key(C->ctx) != 1) {
                        LogError("SSL: client private key doesn't match the certificate -- %s\n", SSLERROR);
                        goto sslerror;
                }
        }
        return C;
sslerror:
        Ssl_free(&C);
        return NULL;
}


void Ssl_free(T *C) {
        ASSERT(C && *C);
        if ((*C)->handler)
                SSL_free((*C)->handler);
        if ((*C)->ctx && ! (*C)->accepted)
                SSL_CTX_free((*C)->ctx);
        FREE((*C)->clientpemfile);
        FREE(*C);
}


void Ssl_close(T C) {
        ASSERT(C);
        SSL_shutdown(C->handler);
        Net_shutdown(C->socket, SHUT_RDWR);
        Net_close(C->socket);
}


boolean_t Ssl_connect(T C, int socket, const char *name) {
        ASSERT(C);
        ASSERT(socket >= 0);
        C->socket = socket;
        SSL_set_connect_state(C->handler);
        SSL_set_fd(C->handler, C->socket);
        _setServerNameIdentification(C, name);
        int rv = SSL_connect(C->handler);
        if (rv < 0) {
                switch (SSL_get_error(C->handler, rv)) {
                        case SSL_ERROR_NONE:
                        case SSL_ERROR_WANT_READ:
                        case SSL_ERROR_WANT_WRITE:
                                break;
                        default:
                                LogError("SSL: connection error -- %s\n", SSLERROR);
                                return false;
                }
        }
        return true;
}


int Ssl_write(T C, void *b, int size, int timeout) {
        ASSERT(C);
        int n = 0;
        if (size > 0) {
                boolean_t retry = false;
                do {
                        switch (SSL_get_error(C->handler, (n = SSL_write(C->handler, b, size)))) {
                                case SSL_ERROR_NONE:
                                case SSL_ERROR_ZERO_RETURN:
                                        return n;
                                case SSL_ERROR_WANT_READ:
                                        n = 0;
                                        errno = EWOULDBLOCK;
                                        retry = Net_canRead(C->socket, timeout);
                                        break;
                                case SSL_ERROR_WANT_WRITE:
                                        n = 0;
                                        errno = EWOULDBLOCK;
                                        retry = Net_canWrite(C->socket, timeout);
                                        break;
                                case SSL_ERROR_SYSCALL:
                                        {
                                                unsigned long error = ERR_get_error();
                                                if (error)
                                                        LogError("SSL: write error -- %s\n", ERR_error_string(error, NULL));
                                                else if (n == 0)
                                                        LogError("SSL: write error -- EOF\n");
                                                else if (n == -1)
                                                        LogError("SSL: write I/O error -- %s\n", STRERROR);
                                        }
                                        return -1;
                                default:
                                        LogError("SSL: write error -- %s\n", SSLERROR);
                                        return -1;
                        }
                } while (retry);
        }
        return n;
}


int Ssl_read(T C, void *b, int size, int timeout) {
        ASSERT(C);
        int n = 0;
        if (size > 0) {
                boolean_t retry = false;
                do {
                        switch (SSL_get_error(C->handler, (n = SSL_read(C->handler, b, size)))) {
                                case SSL_ERROR_NONE:
                                case SSL_ERROR_ZERO_RETURN:
                                        return n;
                                case SSL_ERROR_WANT_READ:
                                        n = 0;
                                        errno = EWOULDBLOCK;
                                        retry = Net_canRead(C->socket, timeout);
                                        break;
                                case SSL_ERROR_WANT_WRITE:
                                        n = 0;
                                        errno = EWOULDBLOCK;
                                        retry = Net_canWrite(C->socket, timeout);
                                        break;
                                case SSL_ERROR_SYSCALL:
                                        {
                                                unsigned long error = ERR_get_error();
                                                if (error)
                                                        LogError("SSL: read error -- %s\n", ERR_error_string(error, NULL));
                                                else if (n == 0)
                                                        LogError("SSL: read error -- EOF\n");
                                                else if (n == -1)
                                                        LogError("SSL: read I/O error -- %s\n", STRERROR);
                                        }
                                        return -1;
                                default:
                                        LogError("SSL: read error -- %s\n", SSLERROR);
                                        return -1;
                        }
                } while (retry);
        }
        return n;
}


boolean_t Ssl_checkCertificate(T C, char *md5sum) {
        ASSERT(C);
        ASSERT(md5sum);
        if (! Run.fipsEnabled) {
                X509 *cert = SSL_get_peer_certificate(C->handler);
                if (! cert) {
                        LogError("SSL: cannot get peer certificate\n");
                        return false;
                }
                unsigned int len, i = 0;
                unsigned char md5[EVP_MAX_MD_SIZE];
                X509_digest(cert, EVP_md5(), md5, &len);
                while ((i < len) && (md5sum[2 * i] != '\0') && (md5sum[2 * i + 1] != '\0')) {
                        unsigned char c = (md5sum[2 * i] > 57 ? md5sum[2 * i] - 87 : md5sum[2 * i] - 48) * 0x10 + (md5sum[2 * i + 1] > 57 ? md5sum[2 * i + 1] - 87 : md5sum[2 * i + 1] - 48);
                        if (c != md5[i]) {
                                X509_free(cert);
                                return false;
                        }
                        i++;
                }
                X509_free(cert);
                return true;
        } else {
                LogError("SSL: certificate checksum error -- MD5 not supported in FIPS mode\n");
                return false;
        }
}


/* -------------------------------------------------------------- SSL Server */


SslServer_T SslServer_new(char *pemfile, char *clientpemfile, int socket) {
        ASSERT(pemfile);
        ASSERT(socket >= 0);
        SslServer_T S;
        NEW(S);
        S->socket = socket;
        S->pemfile = Str_dup(pemfile);
        if (clientpemfile)
                S->clientpemfile = Str_dup(clientpemfile);
        const SSL_METHOD *method = SSLv23_server_method();
        if (! method) {
                LogError("SSL: server method initialization failed -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (! (S->ctx = SSL_CTX_new(method))) {
                LogError("SSL: server context initialization failed -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (SSL_CTX_set_cipher_list(S->ctx, CIPHER_LIST) != 1) {
                LogError("SSL: server cipher list [%s] error -- no valid ciphers\n", CIPHER_LIST);
                goto sslerror;
        }
        SSL_CTX_set_options(S->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
#ifdef SSL_OP_NO_COMPRESSION
        SSL_CTX_set_options(S->ctx, SSL_OP_NO_COMPRESSION);
#endif
        SSL_CTX_set_session_cache_mode(S->ctx, SSL_SESS_CACHE_OFF);
        if (SSL_CTX_use_certificate_chain_file(S->ctx, pemfile) != 1) {
                LogError("SSL: server certificate chain loading failed -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (SSL_CTX_use_PrivateKey_file(S->ctx, pemfile, SSL_FILETYPE_PEM) != 1) {
                LogError("SSL: server private key loading failed -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (SSL_CTX_check_private_key(S->ctx) != 1) {
                LogError("SSL: server private key doesn't match the certificate -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (S->clientpemfile) {
                struct stat sb;
                if (stat(S->clientpemfile, &sb) == -1) {
                        LogError("SSL: client PEM file %s error -- %s\n", Run.httpd.socket.net.ssl.clientpem, STRERROR);
                        goto sslerror;
                }
                if (S_ISDIR(sb.st_mode)) {
                        if (! SSL_CTX_load_verify_locations(S->ctx, NULL , S->clientpemfile)) {
                                LogError("SSL: client PEM file CA certificates %s loading failed -- %s\n", Run.httpd.socket.net.ssl.clientpem, SSLERROR);
                                goto sslerror;
                        }
                } else if (S_ISREG(sb.st_mode)) {
                        if (! SSL_CTX_load_verify_locations(S->ctx, S->clientpemfile, NULL)) {
                                LogError("SSL: client PEM file CA certificates %s loading failed -- %s\n", Run.httpd.socket.net.ssl.clientpem, SSLERROR);
                                goto sslerror;
                        }
                        SSL_CTX_set_client_CA_list(S->ctx, SSL_load_client_CA_file(S->clientpemfile));
                } else {
                        LogError("SSL: client PEM %s is not file nor directory\n", S->clientpemfile);
                        goto sslerror;
                }
                // Load server certificate for monit CLI authentication
                if (! SSL_CTX_load_verify_locations(S->ctx, S->pemfile, NULL)) {
                        LogError("SSL: server certificate CA certificates %s loading failed -- %s\n", S->pemfile, SSLERROR);
                        goto sslerror;
                }
                SSL_CTX_set_verify(S->ctx, SSL_VERIFY_PEER, _verifyCertificates);
        } else {
                SSL_CTX_set_verify(S->ctx, SSL_VERIFY_NONE, NULL);
        }
        return S;
sslerror:
        SslServer_free(&S);
        return NULL;
}


void SslServer_free(SslServer_T *S) {
        ASSERT(S && *S);
        if ((*S)->ctx)
                SSL_CTX_free((*S)->ctx);
        FREE((*S)->pemfile);
        FREE((*S)->clientpemfile);
        FREE(*S);
}


T SslServer_newConnection(SslServer_T S) {
        ASSERT(S);
        T C;
        NEW(C);
        C->accepted = true;
        C->ctx = S->ctx;
        if (! (C->handler = SSL_new(C->ctx))) {
                LogError("SSL: server cannot create handler -- %s\n", SSLERROR);
                Ssl_free(&C);
                return NULL;
        }
        SSL_set_mode(C->handler, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        if (S->clientpemfile)
                C->clientpemfile = Str_dup(S->clientpemfile);
        return C;
}


void SslServer_freeConnection(SslServer_T S, T *C) {
        ASSERT(S);
        ASSERT(C && *C);
        Ssl_close(*C);
        Ssl_free(C);
}


boolean_t SslServer_accept(T C, int socket) {
        ASSERT(C);
        ASSERT(socket >= 0);
        C->socket = socket;
        SSL_set_accept_state(C->handler);
        SSL_set_fd(C->handler, C->socket);
        int rv = SSL_accept(C->handler);
        if (rv < 0) {
                switch (SSL_get_error(C->handler, rv)) {
                        case SSL_ERROR_NONE:
                        case SSL_ERROR_WANT_READ:
                        case SSL_ERROR_WANT_WRITE:
                                break;
                        default:
                                LogError("SSL: accept error -- %s\n", SSLERROR);
                                return false;
                }
        }
        if (C->clientpemfile) {
                X509 *cert = SSL_get_peer_certificate(C->handler);
                if (! cert) {
                        LogError("SSL: client didn't send a client certificate\n");
                        return false;
                }
                X509_free(cert);
                long rv = SSL_get_verify_result(C->handler);
                if (rv != X509_V_OK) {
                        LogError("SSL: client certificate verification failed -- %s\n", X509_verify_cert_error_string(rv));
                        return false;
                }
        }
        return true;
}

#endif

