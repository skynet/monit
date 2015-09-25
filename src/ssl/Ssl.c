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
#include "system/Time.h"
#include "exceptions/AssertException.h"
#include "exceptions/IOException.h"


/**
 *  SSL implementation
 *
 *  @file
 */
//FIXME: refactor Ssl_connect(), Ssl_write() and Ssl_read() + SslServer_accept (and the whole network layer) to be really non-blocking


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
        boolean_t allowSelfSignedCertificates;
        Ssl_Version version;
        int socket;
        int minimumValidDays;
        SSL *handler;
        SSL_CTX *ctx;
        X509 *certificate;
        char *clientpemfile;
        MD_T checksum;
        char error[128];
};


struct SslServer_T {
        int socket;
        SSL_CTX *ctx;
        char *pemfile;
        char *clientpemfile;
};


static Mutex_T *instanceMutexTable;
static int session_id_context = 1;


/* ----------------------------------------------------------------- Private */


static unsigned long _threadID() {
        return (unsigned long)Thread_self();
}


static boolean_t _retry(int socket, int *timeout, int (*callback)(int socket, time_t milliseconds)) {
        long long start = Time_milli();
        if (callback(socket, *timeout) && ! (Run.flags & Run_Stopped)) {
                long long stop = Time_milli();
                if (stop >= start && (*timeout -= stop - start) > 0 && ! (Run.flags & Run_Stopped)) // Reduce timeout with guard against backward clock jumps
                        return true;
        }
        return false;
}


static void _mutexLock(int mode, int n, const char *file, int line) {
        if (mode & CRYPTO_LOCK)
                Mutex_lock(instanceMutexTable[n]);
        else
                Mutex_unlock(instanceMutexTable[n]);
}


static int _checkExpiration(T C, X509_STORE_CTX *ctx, X509 *certificate) {
        if (C->minimumValidDays) {
                // If we have warn-X-days-before-expire condition, check the certificate validity (already expired certificates are catched in preverify => we don't need to handle them here).
                int deltadays = 0;
#ifdef HAVE_ASN1_TIME_DIFF
                int deltaseconds;
                if (! ASN1_TIME_diff(&deltadays, &deltaseconds, NULL, X509_get_notAfter(certificate))) {
                        X509_STORE_CTX_set_error(ctx, X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD);
                        snprintf(C->error, sizeof(C->error), "invalid time format (in certificate's notAfter field)");
                        return 0;
                }
#else
                ASN1_GENERALIZEDTIME *t = ASN1_TIME_to_generalizedtime(X509_get_notAfter(certificate), NULL);
                if (! t) {
                        X509_STORE_CTX_set_error(ctx, X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD);
                        snprintf(C->error, sizeof(C->error), "invalid time format (in certificate's notAfter field)");
                        return 0;
                }
                TRY
                {
                        deltadays = (double)(Time_toTimestamp((const char *)t->data) - Time_now()) / 86400.;
                }
                ELSE
                {
                        X509_STORE_CTX_set_error(ctx, X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD);
                        snprintf(C->error, sizeof(C->error), "invalid time format (in certificate's notAfter field) -- %s", t->data);
                }
                FINALLY
                {
                        ASN1_STRING_free(t);
                }
                END_TRY;
#endif
                if (deltadays < C->minimumValidDays) {
                        X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
                        snprintf(C->error, sizeof(C->error), "the certificate will expire in %d days, please renew it", deltadays);
                        return 0;
                }
        }
        return 1;
}


static int _checkChecksum(T C, X509_STORE_CTX *ctx, X509 *certificate) {
        if (X509_STORE_CTX_get_error_depth(ctx) == 0 && *C->checksum) {
                if (! (Run.flags & Run_FipsEnabled)) {
                        unsigned int len, i = 0;
                        unsigned char md5[EVP_MAX_MD_SIZE];
                        X509_digest(certificate, EVP_md5(), md5, &len);
                        while ((i < len) && (C->checksum[2 * i] != '\0') && (C->checksum[2 * i + 1] != '\0')) {
                                unsigned char c = (C->checksum[2 * i] > 57 ? C->checksum[2 * i] - 87 : C->checksum[2 * i] - 48) * 0x10 + (C->checksum[2 * i + 1] > 57 ? C->checksum[2 * i + 1] - 87 : C->checksum[2 * i + 1] - 48);
                                if (c != md5[i]) {
                                        X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
                                        snprintf(C->error, sizeof(C->error), "SSL server certificate checksum failed");
                                        return 0;
                                }
                                i++;
                        }
                } else {
                        X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
                        snprintf(C->error, sizeof(C->error), "SSL certificate checksum skipped -- MD5 not supported in FIPS mode");
                        return 0;
                }
        }
        return 1;
}


static int _verifyServerCertificates(int preverify_ok, X509_STORE_CTX *ctx) {
        T C = SSL_get_app_data(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
        if (! C) {
                LogError("SSL: cannot get application data");
                return 0;
        }
        *C->error = 0;
        if (! preverify_ok) {
                int error = X509_STORE_CTX_get_error(ctx);
                switch (error) {
                        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
                                if (C->allowSelfSignedCertificates) {
                                        X509_STORE_CTX_set_error(ctx, X509_V_OK);
                                        return 1;
                                }
                                snprintf(C->error, sizeof(C->error), "self signed certificate is not allowed, please use a trusted certificate or use the 'allowselfcertification' option");
                                break;
                        default:
                                break;
                }
        } else {
                X509 *certificate = X509_STORE_CTX_get_current_cert(ctx);
                if (certificate) {
                        return (_checkExpiration(C, ctx, certificate) && _checkChecksum(C, ctx, certificate));
                } else {
                        X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
                        snprintf(C->error, sizeof(C->error), "cannot get SSL server certificate");
                        return 0;
                }
        }
        return 0;
}


static int _verifyClientCertificates(int preverify_ok, X509_STORE_CTX *ctx) {
        if (! preverify_ok) {
                int error = X509_STORE_CTX_get_error(ctx);
                switch (error) {
                        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
                                if (! (Run.httpd.flags & Httpd_AllowSelfSignedCertificates)) {
                                        LogError("SSL: self-signed certificate is not allowed\n");
                                        return 0;
                                }
                                X509_STORE_CTX_set_error(ctx, X509_V_OK); // Reset error if we accept self-signed certificates
                                break;
                        case X509_V_ERR_INVALID_PURPOSE:
                                break;
                        default:
                                LogError("SSL: invalid certificate -- %s\n", X509_verify_cert_error_string(error));
                                return 0;
                }
        }
        X509_OBJECT found_cert;
        if (X509_STORE_CTX_get_error_depth(ctx) == 0 && X509_STORE_get_by_subject(ctx, X509_LU_X509, X509_get_subject_name(X509_STORE_CTX_get_current_cert(ctx)), &found_cert) != 1) {
                LogError("SSL: no matching certificate found -- %s\n", SSLERROR);
                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
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
                        DEBUG("SSL: unable to set the SNI extension to %s\n", hostname);
                        return false;
                }
#endif
        return true;
}


static boolean_t _setClientCertificate(T C, const char *file) {
        if (SSL_CTX_use_certificate_chain_file(C->ctx, file) != 1) {
                LogError("SSL client certificate chain loading failed: %s\n", SSLERROR);
                return false;
        }
        if (SSL_CTX_use_PrivateKey_file(C->ctx, file, SSL_FILETYPE_PEM) != 1) {
                LogError("SSL client private key loading failed: %s\n", SSLERROR);
                return false;
        }
        if (SSL_CTX_check_private_key(C->ctx) != 1) {
                LogError("SSL client private key doesn't match the certificate: %s\n", SSLERROR);
                return false;
        }
        C->clientpemfile = Str_dup(file);
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


T Ssl_new(Ssl_Version version, const char *clientpem) {
        T C;
        NEW(C);
        C->version = version;
        const SSL_METHOD *method;
        switch (version) {
                case SSL_V2:
#ifdef OPENSSL_NO_SSL2
                        LogError("SSL: SSLv2 not supported\n");
                        goto sslerror;
#else
                        if (Run.flags & Run_FipsEnabled) {
                                LogError("SSL: SSLv2 is not allowed in FIPS mode -- use TLS\n");
                                goto sslerror;
                        }
                        method = SSLv2_client_method();
#endif
                        break;
                case SSL_V3:
#ifdef OPENSSL_NO_SSL3
                        LogError("SSL: SSLv3 not supported\n");
                        goto sslerror;
#else
                        if (Run.flags & Run_FipsEnabled) {
                                LogError("SSL: SSLv3 is not allowed in FIPS mode -- use TLS\n");
                                goto sslerror;
                        }
                        method = SSLv3_client_method();
#endif
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
        if (clientpem && ! _setClientCertificate(C, clientpem))
                goto sslerror;
        SSL_CTX_set_default_verify_paths(C->ctx);
        SSL_CTX_set_verify(C->ctx, SSL_VERIFY_PEER, _verifyServerCertificates);
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
        SSL_set_app_data(C->handler, C);
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


void Ssl_connect(T C, int socket, int timeout, const char *name) {
        ASSERT(C);
        ASSERT(socket >= 0);
        C->socket = socket;
        SSL_set_connect_state(C->handler);
        SSL_set_fd(C->handler, C->socket);
        _setServerNameIdentification(C, name);
        boolean_t retry = false;
        do {
                int rv = SSL_connect(C->handler);
                if (rv < 0) {
                        switch (SSL_get_error(C->handler, rv)) {
                                case SSL_ERROR_NONE:
                                        break;
                                case SSL_ERROR_WANT_READ:
                                        retry = _retry(C->socket, &timeout, Net_canRead);
                                        break;
                                case SSL_ERROR_WANT_WRITE:
                                        retry = _retry(C->socket, &timeout, Net_canWrite);
                                        break;
                                default:
					rv = (int)SSL_get_verify_result(C->handler);
					if (rv != X509_V_OK)
                                                THROW(IOException, "SSL server certificate verification error: %s", *C->error ? C->error : X509_verify_cert_error_string(rv));
					else
                                                THROW(IOException, "SSL connection error: %s", SSLERROR);
                                        break;
                        }
                } else {
                        break;
                }
        } while (retry);
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
                                        retry = _retry(C->socket, &timeout, Net_canRead);
                                        break;
                                case SSL_ERROR_WANT_WRITE:
                                        n = 0;
                                        errno = EWOULDBLOCK;
                                        retry = _retry(C->socket, &timeout, Net_canWrite);
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
                                        retry = _retry(C->socket, &timeout, Net_canRead);
                                        break;
                                case SSL_ERROR_WANT_WRITE:
                                        n = 0;
                                        errno = EWOULDBLOCK;
                                        retry = _retry(C->socket, &timeout, Net_canWrite);
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


void Ssl_setAllowSelfSignedCertificates(T C, boolean_t allow) {
        ASSERT(C);
        C->allowSelfSignedCertificates = allow;
}


void Ssl_setCertificateMinimumValidDays(T C, int days) {
        ASSERT(C);
        C->minimumValidDays = days;
}


void Ssl_setCertificateChecksum(T C, const char *checksum) {
        ASSERT(C);
        if (checksum)
                snprintf(C->checksum, sizeof(C->checksum), "%s", checksum);
        else
                *C->checksum = 0;
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
        if (SSL_CTX_set_session_id_context(S->ctx, (void *)&session_id_context, sizeof(session_id_context)) != 1) {
                LogError("SSL: server session id context initialization failed -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (SSL_CTX_set_cipher_list(S->ctx, CIPHER_LIST) != 1) {
                LogError("SSL: server cipher list [%s] error -- no valid ciphers\n", CIPHER_LIST);
                goto sslerror;
        }
#ifdef SSL_MODE_RELEASE_BUFFERS
        SSL_CTX_set_mode(S->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
        SSL_CTX_set_options(S->ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif
#ifdef SSL_CTRL_SET_ECDH_AUTO
        SSL_CTX_set_options(S->ctx, SSL_OP_SINGLE_ECDH_USE);
        SSL_CTX_set_ecdh_auto(S->ctx, 1);
#elif defined HAVE_EC_KEY
        SSL_CTX_set_options(S->ctx, SSL_OP_SINGLE_ECDH_USE);
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (key) {
                SSL_CTX_set_tmp_ecdh(S->ctx, key);
                EC_KEY_free(key);
        }
#endif
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
                LogError("SSL: server private key do not match the certificate -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (S->clientpemfile) {
                struct stat sb;
                if (stat(S->clientpemfile, &sb) == -1) {
                        LogError("SSL: client PEM file %s error -- %s\n", Run.httpd.socket.net.ssl.clientpem, STRERROR);
                        goto sslerror;
                }
                if (! S_ISREG(sb.st_mode)) {
                        LogError("SSL: client PEM file %s is not a file\n", S->clientpemfile);
                        goto sslerror;
                }
                if (! SSL_CTX_load_verify_locations(S->ctx, S->clientpemfile, NULL)) {
                        LogError("SSL: client PEM file CA certificates %s loading failed -- %s\n", Run.httpd.socket.net.ssl.clientpem, SSLERROR);
                        goto sslerror;
                }
                SSL_CTX_set_client_CA_list(S->ctx, SSL_load_client_CA_file(S->clientpemfile));
                if (! SSL_CTX_load_verify_locations(S->ctx, S->pemfile, NULL)) {
                        LogError("SSL: server certificate CA certificates %s loading failed -- %s\n", S->pemfile, SSLERROR);
                        goto sslerror;
                }
                SSL_CTX_set_verify(S->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, _verifyClientCertificates);
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


boolean_t SslServer_accept(T C, int socket, int timeout) {
        ASSERT(C);
        ASSERT(socket >= 0);
        C->socket = socket;
        SSL_set_accept_state(C->handler);
        SSL_set_fd(C->handler, C->socket);
        boolean_t retry = false;
        do {
                int rv = SSL_accept(C->handler);
                if (rv < 0) {
                        switch (SSL_get_error(C->handler, rv)) {
                                case SSL_ERROR_NONE:
                                        break;
                                case SSL_ERROR_WANT_READ:
                                        retry = _retry(C->socket, &timeout, Net_canRead);
                                        break;
                                case SSL_ERROR_WANT_WRITE:
                                        retry = _retry(C->socket, &timeout, Net_canWrite);
                                        break;
                                default:
                                        rv = (int)SSL_get_verify_result(C->handler);
                                        if (rv != X509_V_OK)
                                                LogError("SSL client certificate verification error: %s\n", *C->error ? C->error : X509_verify_cert_error_string(rv));
                                        else
                                                LogError("SSL accept error: %s\n", SSLERROR);
                                        return false;
                        }
                } else {
                        break;
                }
        } while (retry);
        return true;
}

#endif

