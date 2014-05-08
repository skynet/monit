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

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
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

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
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
#include <openssl/bio.h>

#include "monit.h"
#include "net.h"
#include "ssl.h"

// libmonit
#include "system/Net.h"


/* -------------------------------------------------------------- Prototypes */


#define SSLERROR ERR_error_string(ERR_get_error(),NULL)

static int unsigned long ssl_thread_id();
static void ssl_mutex_lock(int, int n, const char *, int );
static int verify_init(ssl_server_connection *);
static int verify_callback(int, X509_STORE_CTX *);
static int check_preverify(X509_STORE_CTX *);
static void cleanup_ssl_socket(ssl_connection *);
static void cleanup_ssl_server_socket(ssl_server_connection *);
static int handle_error(int, ssl_connection *);
static int update_ssl_cert_data(ssl_connection *);
static ssl_server_connection *new_ssl_server_connection(char *, char *);
static int start_ssl();

static int              ssl_initialized          = FALSE;
static pthread_mutex_t  ssl_mutex                = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t *ssl_mutex_table;


/* ------------------------------------------------------------- Definitions */


/**
 * Number of random bytes to obtain
 */
#define RANDOM_BYTES 1024

/**
 * The PRIMARY random device selected for seeding the PRNG. We use a
 * non-blocking pseudo random device, to generate pseudo entropy.
 */
#define URANDOM_DEVICE "/dev/urandom"

/**
 * If a non-blocking device is not found on the system a blocking
 * entropy producer is tried instead.
 */
#define RANDOM_DEVICE "/dev/random"


/* The list of all ciphers suites in order of strength except those containing
 anonymous DH ciphers, low  bit-size ciphers, export-crippled ciphers or the
 MD5 hash algorithm */
#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"


/**
 *  SSL Socket methods.
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * Embeds a socket in a ssl connection.
 * @param socket the socket to be used.
 * @return The ssl connection or NULL if an error occured.
 */
int embed_ssl_socket(ssl_connection *ssl, int socket) {
        int ssl_error;
        time_t ssl_time;

        if (!ssl)
                return FALSE;

        if (!ssl_initialized)
                start_ssl();

        if (socket >= 0) {
                ssl->socket = socket;
        } else {
                LogError("SSL socket error\n");
                goto sslerror;
        }

        if ((ssl->handler = SSL_new (ssl->ctx)) == NULL) {
                LogError("Cannot initialize the SSL handler -- %s\n", SSLERROR);
                goto sslerror;
        }

        if (SSL_CTX_set_cipher_list(ssl->ctx, CIPHER_LIST) != 1) {
                LogError("Error setting cipher list '%s' (no valid ciphers)", CIPHER_LIST);
                goto sslerror;
        }

        Net_setNonBlocking(ssl->socket);

        if ((ssl->socket_bio = BIO_new_socket(ssl->socket, BIO_NOCLOSE)) == NULL) {
                LogError("Cannot create IO buffer -- %s\n", SSLERROR);
                goto sslerror;
        }

        SSL_set_bio(ssl->handler, ssl->socket_bio, ssl->socket_bio);
        ssl_time = time(NULL);

        while ((ssl_error = SSL_connect (ssl->handler)) < 0) {
                if ((time(NULL) - ssl_time) > SSL_TIMEOUT) {
                        LogError("SSL service timeout\n");
                        goto sslerror;
                }

                if (!handle_error(ssl_error, ssl))
                        goto sslerror;

                if (!BIO_should_retry(ssl->socket_bio))
                        goto sslerror;
        }

        ssl->cipher = (char *) SSL_get_cipher(ssl->handler);

        if (! update_ssl_cert_data(ssl)) {
                LogError("Cannot get the SSL server certificate\n");
                goto sslerror;
        }

        return TRUE;

sslerror:
        cleanup_ssl_socket(ssl);
        return FALSE;
}


/**
 * Compare certificate with given md5 sum
 * @param ssl reference to ssl connection
 * @param md5sum string of the md5sum to test against
 * @return TRUE, if sums do not match FALSE
 */
int check_ssl_md5sum(ssl_connection *ssl, char *md5sum) {
        unsigned int i = 0;

        ASSERT(md5sum);

        while ((i < ssl->cert_md5_len) && (md5sum[2*i] != '\0') && (md5sum[2*i+1] != '\0')) {
                unsigned char c = (md5sum[2*i] > 57 ? md5sum[2*i] - 87 : md5sum[2*i] - 48) * 0x10+ (md5sum[2*i+1] > 57 ? md5sum[2*i+1] - 87 : md5sum[2*i+1] - 48);
                if (c != ssl->cert_md5[i])
                        return FALSE;
                i++;
        }
        return TRUE;
}


/**
 * Closes a ssl connection (ssl socket + net socket)
 * @param ssl ssl connection
 * @return TRUE, or FALSE if an error has occured.
 */
int close_ssl_socket(ssl_connection *ssl) {
        int rv;

        if (!ssl)
                return FALSE;

        if (! (rv = SSL_shutdown(ssl->handler))) {
                shutdown(ssl->socket, 1);
                rv = SSL_shutdown(ssl->handler);
        }

        Net_close(ssl->socket);
        cleanup_ssl_socket(ssl);

        return (rv > 0) ? TRUE : FALSE;
}


/**
 * Garbage collection for non-reusable parts a ssl connection
 * @param ssl ssl connection
 */
void delete_ssl_socket(ssl_connection *ssl) {
        if (!ssl)
                return;

        cleanup_ssl_socket(ssl);

        if (ssl->ctx && !ssl->accepted)
                SSL_CTX_free(ssl->ctx);

        ssl->ctx = NULL;

        FREE(ssl);
}


/**
 * Initializes a ssl connection for server use.
 * @param pemfilename Filename for the key/cert file
 * @return An ssl connection, or NULL if an error occured.
 */
ssl_server_connection *init_ssl_server(char *pemfile, char *clientpemfile) {
        SSL_METHOD *server_method = NULL;
        ssl_server_connection *ssl_server;
        ASSERT(pemfile);
        if (!ssl_initialized)
                start_ssl();

        ssl_server = new_ssl_server_connection(pemfile, clientpemfile);
#ifdef OPENSSL_FIPS
        if (FIPS_mode())
                server_method = TLSv1_server_method();
        else
#endif
                server_method = SSLv23_server_method();
        if (!(ssl_server->method = server_method)) {
                LogError("Cannot initialize the SSL method -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (!(ssl_server->ctx = SSL_CTX_new(ssl_server->method))) {
                LogError("Cannot initialize SSL server certificate handler -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (SSL_CTX_use_certificate_chain_file(ssl_server->ctx, pemfile) != 1) {
                LogError("Cannot initialize SSL server certificate -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_server->ctx, pemfile, SSL_FILETYPE_PEM) != 1) {
                LogError("Cannot initialize SSL server private key -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (SSL_CTX_check_private_key(ssl_server->ctx) != 1) {
                LogError("The private key doesn't match the certificate public key -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (SSL_CTX_set_cipher_list(ssl_server->ctx, CIPHER_LIST) != 1) {
                LogError("Error setting cipher list '%s' (no valid ciphers)", CIPHER_LIST);
                goto sslerror;
        }
        /* Disable session cache */
        SSL_CTX_set_session_cache_mode(ssl_server->ctx, SSL_SESS_CACHE_OFF);
        /*
         * We need this to force transmission of client certs
         */
        if (!verify_init(ssl_server)) {
                LogError("Verification engine was not properly initialized -- %s\n", SSLERROR);
                goto sslerror;
        }
        if (ssl_server->clientpemfile) {
                STACK_OF(X509_NAME) *stack = SSL_CTX_get_client_CA_list(ssl_server->ctx);
                LogInfo("Found %d client certificates\n", sk_X509_NAME_num(stack));
        }
        return ssl_server;
sslerror:
        delete_ssl_server_socket(ssl_server);
        return NULL;
}


/**
 * Deletes a SSL server connection.
 * @param ssl_server data for ssl server connection
 */
void delete_ssl_server_socket(ssl_server_connection *ssl_server) {
        if (!ssl_server)
                return;

        cleanup_ssl_server_socket(ssl_server);

        if (ssl_server->ctx)
                SSL_CTX_free(ssl_server->ctx);

        FREE(ssl_server);
}


/**
 * Inserts an SSL connection in the connection list of a server.
 * @param ssl_server data for ssl server connection
 * @return new SSL connection for the connection, or NULL if failed
 */
ssl_connection *insert_accepted_ssl_socket(ssl_server_connection *ssl_server) {
        ssl_connection *ssl;

        ASSERT(ssl_server);

        if (!ssl_initialized)
                start_ssl();

        NEW(ssl);
        ssl->method = NULL;
        ssl->handler = NULL;
        ssl->cert = NULL;
        ssl->cipher = NULL;
        ssl->socket = 0;
        ssl->next = NULL;
        ssl->accepted = FALSE;
        ssl->cert_md5 = NULL;
        ssl->cert_md5_len = 0;
        ssl->clientpemfile = NULL;

        if (ssl_server->clientpemfile != NULL)
                ssl->clientpemfile = Str_dup(ssl_server->clientpemfile);

        LOCK(ssl_mutex);

        ssl->prev = NULL;
        ssl->next = ssl_server->ssl_conn_list;

        if ( ssl->next != NULL )
                ssl->next->prev = ssl;

        END_LOCK;

        ssl_server->ssl_conn_list = ssl;
        ssl->ctx = ssl_server->ctx;
        ssl->accepted = TRUE;

        return ssl;
}


/**
 * Closes an accepted SSL server connection and deletes it form the
 * connection list.
 * @param ssl_server data for ssl server connection
 * @param ssl data the connection to be deleted
 */
void close_accepted_ssl_socket(ssl_server_connection *ssl_server, ssl_connection *ssl) {
        if (!ssl || !ssl_server)
                return;

        Net_close(ssl->socket);

        LOCK(ssl_mutex);

        if (ssl->prev == NULL)
                ssl_server->ssl_conn_list = ssl->next;
        else
                ssl->prev->next = ssl->next;

        END_LOCK;

        delete_ssl_socket(ssl);
}


/**
 * Embeds an accepted server socket in an existing ssl connection.
 * @param ssl ssl connection
 * @param socket the socket to be used.
 * @return TRUE, or FALSE if an error has occured.
 */
int embed_accepted_ssl_socket(ssl_connection *ssl, int socket) {
        int ssl_error;
        time_t ssl_time;

        ASSERT(ssl);

        ssl->socket = socket;

        if (!ssl_initialized)
                start_ssl();

        if (!(ssl->handler = SSL_new(ssl->ctx))) {
                LogError("Cannot initialize the SSL handler -- %s\n", SSLERROR);
                return FALSE;
        }

        if (socket < 0) {
                LogError("SSL socket error\n");
                return FALSE;
        }

        Net_setNonBlocking(ssl->socket);

        if (!(ssl->socket_bio = BIO_new_socket(ssl->socket, BIO_NOCLOSE))) {
                LogError("Cannot create IO buffer -- %s\n", SSLERROR);
                return FALSE;
        }

        SSL_set_bio(ssl->handler, ssl->socket_bio, ssl->socket_bio);

        ssl_time = time(NULL);

        while ((ssl_error = SSL_accept(ssl->handler)) < 0) {

                if ((time(NULL) - ssl_time) > SSL_TIMEOUT) {
                        LogError("SSL service timeout\n");
                        return FALSE;
                }

                if (!handle_error(ssl_error, ssl))
                        return FALSE;

                if (!BIO_should_retry(ssl->socket_bio))
                        return FALSE;

        }

        ssl->cipher = (char *)SSL_get_cipher(ssl->handler);

        if (!update_ssl_cert_data(ssl) && ssl->clientpemfile) {
                LogError("The client did not supply a required client certificate\n");
                return FALSE;
        }

        if (SSL_get_verify_result(ssl->handler) > 0) {
                LogError("Verification of the certificate has failed\n");
                return FALSE;
        }

        return TRUE;
}


/**
 * Send data package though the ssl connection
 * @param ssl ssl connection
 * @param buffer array containg the data
 * @param len size of the data container
 * @param timeout Seconds to wait for data to be written
 * @return number of bytes transmitted, -1 in case of an error
 */
int send_ssl_socket(ssl_connection *ssl, void *buffer, size_t len, int timeout) {
        int n = 0;

        ASSERT(ssl);

        do {
                n = SSL_write(ssl->handler, buffer, (int)len);
        } while (n <= 0 && BIO_should_retry(ssl->socket_bio) && can_write(ssl->socket, timeout));

        return (n > 0) ? n : -1;
}


/**
 * Receive data package though the ssl connection
 * @param ssl ssl connection
 * @param buffer array to hold the data
 * @param len size of the data container
 * @param timeout Seconds to wait for data to be available
 * @return number of bytes transmitted, -1 in case of an error
 */
int recv_ssl_socket(ssl_connection *ssl, void *buffer, int len, int timeout) {
        int n = 0;

        ASSERT(ssl);

        do {
                n = SSL_read(ssl->handler, buffer, len);
        } while (n < 0 && BIO_should_retry(ssl->socket_bio) && can_read(ssl->socket, timeout));

        return (n >= 0) ? n : -1;
}


/**
 * Stop SSL support library
 * @return TRUE, or FALSE if an error has occured.
 */
void stop_ssl() {
        if (ssl_initialized) {
                int i;
                ssl_initialized = FALSE;
                ERR_free_strings();
                CRYPTO_set_id_callback(NULL);
                CRYPTO_set_locking_callback(NULL);
                for (i = 0; i < CRYPTO_num_locks(); i++)
                        assert(pthread_mutex_destroy(&ssl_mutex_table[i]) == 0);
                FREE(ssl_mutex_table);
                RAND_cleanup();
        }
}


/**
 * Generate a new ssl connection
 * @return ssl connection container
 */
ssl_connection *new_ssl_connection(char *clientpemfile, int sslversion) {
        ssl_connection *ssl;

        if (!ssl_initialized)
                start_ssl();

        NEW(ssl);
        ssl->socket_bio = NULL;
        ssl->handler = NULL;
        ssl->cert = NULL;
        ssl->cipher = NULL;
        ssl->socket = 0;
        ssl->next = NULL;
        ssl->accepted = FALSE;
        ssl->cert_md5 = NULL;
        ssl->cert_md5_len = 0;
        ssl->clientpemfile = clientpemfile ? Str_dup(clientpemfile) : NULL;

        switch (sslversion) {

                case SSL_VERSION_AUTO:
#ifdef OPENSSL_FIPS
                        if (FIPS_mode()) {
                                ssl->method = TLSv1_client_method();
                        } else
#endif
                                ssl->method = SSLv23_client_method();
                        break;

                case SSL_VERSION_SSLV2:
#ifdef OPENSSL_NO_SSL2
                        LogError("SSLv2 is not allowed - use either SSLv3 or TLSv1");
                        goto sslerror;
#else
#ifdef OPENSSL_FIPS
                        if (FIPS_mode()) {
                                LogError("SSLv2 is not allowed in FIPS mode - use TLSv1");
                                goto sslerror;
                        } else
#endif
                                ssl->method = SSLv2_client_method();
#endif
                        break;

                case SSL_VERSION_SSLV3:
#ifdef OPENSSL_FIPS
                        if (FIPS_mode()) {
                                LogError("SSLv3 is not allowed in FIPS mode - use TLSv1");
                                goto sslerror;
                        } else
#endif
                                ssl->method = SSLv3_client_method();
                        break;
                case SSL_VERSION_TLSV1:
                        ssl->method = TLSv1_client_method();
                        break;
#ifdef HAVE_TLSV1_1_CLIENT_METHOD
                case SSL_VERSION_TLSV11:
                        ssl->method = TLSv1_1_client_method();
                        break;
#endif
#ifdef HAVE_TLSV1_2_CLIENT_METHOD
                case SSL_VERSION_TLSV12:
                        ssl->method = TLSv1_2_client_method();
                        break;
#endif
                default:
                        ssl->method = TLSv1_client_method();
                        break;

        }

        if (!ssl->method) {
                LogError("Cannot initialize SSL method -- %s\n", SSLERROR);
                goto sslerror;
        }

        if (!(ssl->ctx = SSL_CTX_new(ssl->method))) {
                LogError("Cannot initialize SSL server certificate handler -- %s\n", SSLERROR);
                goto sslerror;
        }

        if (ssl->clientpemfile) {

                if (SSL_CTX_use_certificate_chain_file(ssl->ctx, ssl->clientpemfile) <= 0) {
                        LogError("Cannot initialize SSL server certificate -- %s\n", SSLERROR);
                        goto sslerror;
                }

                if (SSL_CTX_use_PrivateKey_file(ssl->ctx, ssl->clientpemfile, SSL_FILETYPE_PEM) <= 0) {
                        LogError("Cannot initialize SSL server private key -- %s\n", SSLERROR);
                        goto sslerror;
                }

                if (!SSL_CTX_check_private_key(ssl->ctx)) {
                        LogError("Private key does not match the certificate public key -- %s\n", SSLERROR);
                        goto sslerror;
                }

        }

        return ssl;

sslerror:
        delete_ssl_socket(ssl);
        return NULL;
}


/* ----------------------------------------------------------------- Private */


/**
 * Init verification of transmitted client certs
 */
static int verify_init(ssl_server_connection *ssl_server) {
        struct stat stat_buf;

        if (!ssl_server->clientpemfile) {
                SSL_CTX_set_verify(ssl_server->ctx, SSL_VERIFY_NONE, NULL);
                return TRUE;
        }

        if (stat(ssl_server->clientpemfile, &stat_buf) == -1) {
                LogError("Cannot stat the SSL pem path '%s' -- %s\n", Run.httpsslclientpem, STRERROR);
                return FALSE;
        }

        if (S_ISDIR(stat_buf.st_mode)) {

                if (!SSL_CTX_load_verify_locations(ssl_server->ctx, NULL , ssl_server->clientpemfile)) {
                        LogError("Error setting verify directory to %s -- %s\n", Run.httpsslclientpem, SSLERROR);
                        return FALSE;
                }

                LogInfo("Loaded SSL client pem directory '%s'\n", ssl_server->clientpemfile);

                /* Monit's server cert for cli support */

                if (!SSL_CTX_load_verify_locations(ssl_server->ctx, ssl_server->pemfile, NULL)) {
                        LogError("Error loading verify certificates from %s -- %s\n", ssl_server->pemfile, SSLERROR);
                        return FALSE;
                }

                LogInfo("Loaded monit's SSL pem server file '%s'\n", ssl_server->pemfile);

        } else if (S_ISREG(stat_buf.st_mode)) {

                if (!SSL_CTX_load_verify_locations(ssl_server->ctx, ssl_server->clientpemfile, NULL)) {
                        LogError("Error loading verify certificates from %s -- %s\n", Run.httpsslclientpem, SSLERROR);
                        return FALSE;
                }

                LogInfo("Loaded SSL pem client file '%s'\n", ssl_server->clientpemfile);

                /* Monits server cert for cli support ! */

                if (!SSL_CTX_load_verify_locations(ssl_server->ctx, ssl_server->pemfile, NULL)) {
                        LogError("Error loading verify certificates from %s -- %s\n", ssl_server->pemfile, SSLERROR);
                        return FALSE;
                }

                LogInfo("Loaded monit's SSL pem server file '%s'\n", ssl_server->pemfile);

                SSL_CTX_set_client_CA_list(ssl_server->ctx, SSL_load_client_CA_file(ssl_server->clientpemfile));

        } else {
                LogError("SSL client pem path is no file or directory %s\n", ssl_server->clientpemfile);
                return FALSE;
        }

        SSL_CTX_set_verify(ssl_server->ctx, SSL_VERIFY_PEER, verify_callback);

        return TRUE;
}


/**
 * Check the transmitted client certs and a compare with client cert database
 */
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
        char subject[STRLEN];
        X509_OBJECT found_cert;

        X509_NAME_oneline(X509_get_subject_name(ctx->current_cert), subject, STRLEN-1);

        if (!preverify_ok && !check_preverify(ctx))
                return 0;

        if (ctx->error_depth == 0 && X509_STORE_get_by_subject(ctx, X509_LU_X509, X509_get_subject_name(ctx->current_cert), &found_cert) != 1) {
                LogError("SSL connection rejected. No matching certificate found -- %s\n", SSLERROR);
                return 0;
        }

        return 1;
}


/**
 * Analyse errors found before actual verification
 * @return TRUE if successful
 */
static int check_preverify(X509_STORE_CTX *ctx) {
        if ((ctx->error != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) && (ctx->error != X509_V_ERR_INVALID_PURPOSE)) {
                /* Remote site specified a certificate, but it's not correct */
                LogError("SSL connection rejected because certificate verification has failed -- error %i\n", ctx->error);
                /* Reject connection */
                return FALSE;
        }

        if (Run.allowselfcert && (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)) {
                /* Let's accept self signed certs for the moment! */
                LogInfo("SSL connection accepted with self signed certificate\n");
                ctx->error = 0;
                return TRUE;
        }

        /* Reject connection */
        LogError("SSL connection rejected because certificate verification has failed -- error %i\n", ctx->error);
        return FALSE;
}


/**
 * Helper function for the SSL threadding support
 * @return current thread number
 */
static int unsigned long ssl_thread_id() {
        return ((unsigned long) pthread_self());
}


/**
 * Helper function for the SSL threadding support
 */
static void ssl_mutex_lock(int mode, int n, const char *file, int line) {
        if (mode & CRYPTO_LOCK)
                assert(pthread_mutex_lock( & ssl_mutex_table[n]) == 0);
        else
                assert(pthread_mutex_unlock( & ssl_mutex_table[n]) == 0);
}


/**
 * Handle errors during read, write, connect and accept
 * @return TRUE if non fatal, FALSE if non fatal and retry
 */
static int handle_error(int code, ssl_connection *ssl) {
        int ssl_error = SSL_get_error(ssl->handler, code);

        switch (ssl_error) {

                case SSL_ERROR_WANT_READ:
                        if (can_read(ssl->socket, SSL_TIMEOUT))
                                return TRUE;
                        LogError("SSL read timeout error\n");
                        break;

                case SSL_ERROR_WANT_WRITE:
                        if (can_read(ssl->socket, SSL_TIMEOUT))
                                return TRUE;
                        LogError("SSL write timeout error\n");
                        break;

                case SSL_ERROR_SYSCALL:
                        LogError("SSL syscall error: %s\n", STRERROR);
                        break;

                case SSL_ERROR_SSL:
                        LogError("SSL engine error: %s\n", SSLERROR);
                        break;

                default:
                        LogError("SSL error\n");
                        break;

        }

        return FALSE;
}


/**
 * Garbage collection for non reusable parts of the ssl connection
 * @param ssl ssl connection
 */
static void cleanup_ssl_socket(ssl_connection *ssl) {
        if (!ssl)
                return;

        if (ssl->cert) {
                X509_free(ssl->cert);
                ssl->cert = NULL;
        }

        if (ssl->handler) {
                SSL_free(ssl->handler);
                ssl->handler = NULL;
        }

        if (ssl->socket_bio) {
                /* no BIO_free(ssl->socket_bio); necessary, because BIO is freed by ssl->handler */
                ssl->socket_bio = NULL;
        }

        FREE(ssl->cert_issuer);
        FREE(ssl->cert_subject);
        FREE(ssl->cert_md5);
        FREE(ssl->clientpemfile);
}


/**
 * Garbage collection for a SSL server connection.
 * @param ssl_server data for ssl server connection
 */
static void cleanup_ssl_server_socket(ssl_server_connection *ssl_server) {
        if (!ssl_server)
                return;

        FREE(ssl_server->pemfile);
        FREE(ssl_server->clientpemfile);

        while (ssl_server->ssl_conn_list) {
                ssl_connection *ssl = ssl_server->ssl_conn_list;
                ssl_server->ssl_conn_list = ssl_server->ssl_conn_list->next;
                close_accepted_ssl_socket(ssl_server, ssl);
        }
}


/**
 * Updates some data in the ssl connection
 * @param ssl reference to ssl connection
 * @return TRUE, if not successful FALSE
 */
static int update_ssl_cert_data(ssl_connection *ssl) {
        unsigned char md5[EVP_MAX_MD_SIZE];

        ASSERT(ssl);

        if (!(ssl->cert = SSL_get_peer_certificate(ssl->handler)))
                return FALSE;

#ifdef OPENSSL_FIPS
        if (!FIPS_mode()) {
                /* In FIPS-140 mode, MD5 is unavailable. */
#endif
                ssl->cert_issuer = X509_NAME_oneline (X509_get_issuer_name(ssl->cert), 0, 0);
                ssl->cert_subject = X509_NAME_oneline (X509_get_subject_name(ssl->cert), 0, 0);
                X509_digest(ssl->cert, EVP_md5(), md5, &ssl->cert_md5_len);
                ssl->cert_md5 = (unsigned char *)Str_dup((char *)md5);
#ifdef OPENSSL_FIPS
        }
#endif
        return TRUE;
}


/**
 * Generate a new ssl server connection
 * @return ssl server connection container
 */
static ssl_server_connection *new_ssl_server_connection(char * pemfile, char * clientpemfile) {
        ssl_server_connection *ssl_server;

        ASSERT(pemfile);

        NEW(ssl_server);
        ssl_server->ctx = NULL;
        ssl_server->method = NULL;
        ssl_server->server_socket = 0;
        ssl_server->ssl_conn_list = NULL;
        ssl_server->pemfile = Str_dup(pemfile);
        ssl_server->clientpemfile = clientpemfile ? Str_dup(clientpemfile) : NULL;

        return ssl_server;
}

#ifdef OPENSSL_FIPS
/**
 * Enable FIPS mode, if it isn't enabled yet.
 */
void enable_fips_mode() {
        if (!FIPS_mode()) {
                ASSERT(FIPS_mode_set(1));
                LogInfo("FIPS-140 mode is enabled\n");
        }
}
#endif

/**
 * Start SSL support library. It has to be run before the SSL support
 * can be used.
 * @return TRUE, or FALSE if an error has occured.
 */
static int start_ssl() {
        if (! ssl_initialized) {
                int i;
                int locks = CRYPTO_num_locks();

#ifdef OPENSSL_FIPS
                if (Run.fipsEnabled)
                        enable_fips_mode();
#endif

                ssl_initialized = TRUE;
                ERR_load_crypto_strings();
                ssl_mutex_table = CALLOC(locks, sizeof(pthread_mutex_t));
                for (i = 0; i < locks; i++)
                        pthread_mutex_init(&ssl_mutex_table[i], NULL);
                CRYPTO_set_id_callback(ssl_thread_id);
                CRYPTO_set_locking_callback(ssl_mutex_lock);
                SSL_library_init();
                if (file_exist(URANDOM_DEVICE)) {
                        return(RAND_load_file(URANDOM_DEVICE, RANDOM_BYTES)==RANDOM_BYTES);
                } else if (file_exist(RANDOM_DEVICE)) {
                        DEBUG("Gathering entropy from the random device\n");
                        return(RAND_load_file(RANDOM_DEVICE, RANDOM_BYTES)==RANDOM_BYTES);
                }
                return FALSE;
        }

        return TRUE;
}


#endif


