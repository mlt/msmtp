/*
 * mtls-openssl.c
 *
 * This file is part of msmtp, an SMTP client, and of mpop, a POP3 client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011,
 * 2012, 2014, 2016, 2018, 2019, 2020
 * Martin Lambers <marlam@marlam.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER < 0x30300010
# error OpenSSL is too old
#endif

#ifdef HAVE_LIBIDN
# include <idn2.h>
#endif
#ifdef W32_NATIVE
# include <io.h>
#else
# include <unistd.h>
#endif
#include <assert.h>

#include "gettext.h"
#define _(string) gettext(string)
#define N_(string) gettext_noop(string)

#include "xalloc.h"
#include "mtls.h"


struct mtls_internals_t
{
    SSL_CTX *ssl_ctx;
    SSL *ssl;
};


/*
 * mtls_lib_init()
 *
 * see mtls.h
 */

int mtls_lib_init(char **errstr)
{
    return TLS_EOK;
}


/*
 * mtls_cert_info_get()
 *
 * see mtls.h
 */

int mtls_cert_info_get(mtls_t *mtls, mtls_cert_info_t *mtci, char **errstr)
{
    X509 *x509cert;
    X509_NAME *x509_subject;
    X509_NAME *x509_issuer;
    const ASN1_TIME *asn1time;
    struct tm time;
    unsigned int usize;
    const char *errmsg;

    errmsg = _("cannot get TLS certificate info");
    if (!(x509cert = SSL_get_peer_certificate(mtls->internals->ssl)))
    {
        *errstr = xasprintf(_("%s: no certificate was found"), errmsg);
        return TLS_ECERT;
    }
    if (!(x509_subject = X509_get_subject_name(x509cert)))
    {
        *errstr = xasprintf(_("%s: cannot get certificate subject"), errmsg);
        X509_free(x509cert);
        return TLS_ECERT;
    }
    if (!(x509_issuer = X509_get_issuer_name(x509cert)))
    {
        *errstr = xasprintf(_("%s: cannot get certificate issuer"), errmsg);
        X509_free(x509cert);
        return TLS_ECERT;
    }

    /* certificate information */
    usize = 32;
    if (!X509_digest(x509cert, EVP_sha256(), mtci->sha256_fingerprint, &usize))
    {
        *errstr = xasprintf(_("%s: error getting SHA256 fingerprint"), errmsg);
        return TLS_ECERT;
    }
    asn1time = X509_get0_notBefore(x509cert);
    if (ASN1_TIME_to_tm(asn1time, &time) == 0)
    {
        *errstr = xasprintf(_("%s: cannot get activation time"), errmsg);
        X509_free(x509cert);
        mtls_cert_info_free(mtci);
        return TLS_ECERT;
    }
    mtci->activation_time = mktime(&time);
    asn1time = X509_get0_notAfter(x509cert);
    if (ASN1_TIME_to_tm(asn1time, &time) == 0)
    {
        *errstr = xasprintf(_("%s: cannot get expiration time"), errmsg);
        X509_free(x509cert);
        mtls_cert_info_free(mtci);
        return TLS_ECERT;
    }
    mtci->expiration_time = mktime(&time);

    /* subject information */
    mtci->subject_info = X509_NAME_oneline(x509_subject, NULL, 0);

    /* issuer information */
    mtci->issuer_info = X509_NAME_oneline(x509_issuer, NULL, 0);

    X509_free(x509cert);
    return TLS_EOK;
}


/*
 * mtls_check_cert()
 *
 * If the 'mtls->have_trust_file' flag is set, perform a real verification of
 * the peer's certificate. If this succeeds, the connection can be considered
 * secure.
 * If one of the 'mtls->have_*_fingerprint' flags is
 * set, compare the 'mtls->fingerprint' data with the peer certificate's
 * fingerprint. If this succeeds, the connection can be considered secure.
 * If none of these flags is set, perform only a few sanity checks of the
 * peer's certificate. You cannot trust the connection when this succeeds.
 * Used error codes: TLS_ECERT
 */

static int mtls_check_cert(mtls_t *mtls, char **errstr)
{
    X509 *x509cert;
    long status;
    const char *error_msg;
    /* hostname in ASCII format: */
    char *idn_hostname = NULL;
    int match_found;
    /* needed for fingerprint checking */
    unsigned int usize;
    unsigned char fingerprint[32];


    if (mtls->have_trust_file)
    {
        error_msg = _("TLS certificate verification failed");
    }
    else
    {
        error_msg = _("TLS certificate check failed");
    }

    /* Get certificate */
    if (!(x509cert = SSL_get_peer_certificate(mtls->internals->ssl)))
    {
        *errstr = xasprintf(_("%s: no certificate was sent"), error_msg);
        return TLS_ECERT;
    }

    if (mtls->have_sha256_fingerprint)
    {
        usize = 32;
        if (!X509_digest(x509cert, EVP_sha256(), fingerprint, &usize))
        {
            *errstr = xasprintf(_("%s: error getting SHA256 fingerprint"),
                    error_msg);
            X509_free(x509cert);
            return TLS_ECERT;
        }
        if (memcmp(fingerprint, mtls->fingerprint, 32) != 0)
        {
            *errstr = xasprintf(_("%s: the certificate fingerprint "
                        "does not match"), error_msg);
            X509_free(x509cert);
            return TLS_ECERT;
        }
        X509_free(x509cert);
        return TLS_EOK;
    }

    /* Get result of OpenSSL's default verify function */
    if ((status = SSL_get_verify_result(mtls->internals->ssl)) != X509_V_OK)
    {
        if (mtls->have_trust_file
                || (status != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
                    && status != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
                    && status != X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN))
        {
            *errstr = xasprintf("%s: %s", error_msg,
                    X509_verify_cert_error_string(status));
            X509_free(x509cert);
            return TLS_ECERT;
        }
    }
    printf("*** status=%ld\n", status);

    /* Check if 'hostname' matches the one of the subjectAltName extensions of
     * type DNS or the Common Name (CN). */
    /*
#ifdef HAVE_LIBIDN
    idn2_to_ascii_lz(mtls->hostname, &idn_hostname, IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL);
#endif

    match_found = X509_check_host(x509cert, idn_hostname ? idn_hostname : mtls->hostname,
        0, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT | X509_CHECK_FLAG_NO_WILDCARDS, NULL);
    X509_free(x509cert);
    free(idn_hostname);

    if (!match_found)
    {
        *errstr = xasprintf(
                _("%s: the certificate owner does not match hostname %s"),
                error_msg, mtls->hostname);
        return TLS_ECERT;
    }
    */

    return TLS_EOK;
}


/*
 * mtls_init()
 *
 * see mtls.h
 */

int mtls_init(mtls_t *mtls,
        const char *key_file, const char *cert_file, const char *pin,
        const char *trust_file, const char *crl_file,
        const unsigned char *sha256_fingerprint,
        const unsigned char *sha1_fingerprint,
        const unsigned char *md5_fingerprint,
        int min_dh_prime_bits, const char *priorities,
        const char *hostname,
        int no_certcheck,
        char **errstr)
{
    const SSL_METHOD *ssl_method = TLS_client_method();
    X509_VERIFY_PARAM *param = NULL;

    /* FIXME: Implement support for 'min_dh_prime_bits' */
    if (min_dh_prime_bits >= 0)
    {
        *errstr = xasprintf(
                _("cannot set minimum number of DH prime bits for TLS: %s"),
                _("feature not yet implemented for OpenSSL"));
        return TLS_ELIBFAILED;
    }
    /* FIXME: Implement support for 'priorities' */
    if (priorities)
    {
        *errstr = xasprintf(
                _("cannot set priorities for TLS session: %s"),
                _("feature not yet implemented for OpenSSL"));
        return TLS_ELIBFAILED;
    }
    /* FIXME: Implement support for 'crl_file' */
    if (trust_file && crl_file)
    {
        *errstr = xasprintf(
                _("cannot load CRL file: %s"),
                _("feature not yet implemented for OpenSSL"));
        return TLS_ELIBFAILED;
    }

    if (!ssl_method)
    {
        *errstr = xasprintf(_("cannot set TLS method"));
        return TLS_ELIBFAILED;
    }

    mtls->internals = xmalloc(sizeof(struct mtls_internals_t));

    if (!(mtls->internals->ssl_ctx = SSL_CTX_new(ssl_method)))
    {
        *errstr = xasprintf(_("cannot create TLS context: %s"),
                ERR_error_string(ERR_get_error(), NULL));
        free(mtls->internals);
        mtls->internals = NULL;
        return TLS_ELIBFAILED;
    }
    SSL_CTX_set_security_level(mtls->internals->ssl_ctx, 2);

    /* Disable old protocols. */
    (void)SSL_CTX_set_options(mtls->internals->ssl_ctx,
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    if (key_file && cert_file)
    {
        if (SSL_CTX_use_PrivateKey_file(
                    mtls->internals->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1)
        {
            *errstr = xasprintf(_("cannot load key file %s: %s"),
                    key_file, ERR_error_string(ERR_get_error(), NULL));
            SSL_CTX_free(mtls->internals->ssl_ctx);
            free(mtls->internals);
            mtls->internals = NULL;
            return TLS_EFILE;
        }
        if (SSL_CTX_use_certificate_chain_file(mtls->internals->ssl_ctx, cert_file) != 1)
        {
            *errstr = xasprintf(_("cannot load certificate file %s: %s"),
                    cert_file, ERR_error_string(ERR_get_error(), NULL));
            SSL_CTX_free(mtls->internals->ssl_ctx);
            free(mtls->internals);
            mtls->internals = NULL;
            return TLS_EFILE;
        }
    }
    if (trust_file
            && !no_certcheck
            && !sha256_fingerprint
            && !sha1_fingerprint
            && !md5_fingerprint)
    {
        if (strcmp(trust_file, "system") == 0)
        {
            if (SSL_CTX_set_default_verify_paths(mtls->internals->ssl_ctx) != 1)
            {
                *errstr = xasprintf(_("cannot set X509 system trust for TLS session: %s"),
                        ERR_error_string(ERR_get_error(), NULL));
                SSL_CTX_free(mtls->internals->ssl_ctx);
                free(mtls->internals);
                mtls->internals = NULL;
                return TLS_EFILE;
            }
        }
        else
        {
            if (SSL_CTX_load_verify_locations(mtls->internals->ssl_ctx, trust_file, NULL) != 1)
            {
                *errstr = xasprintf(_("cannot load trust file %s: %s"),
                        trust_file, ERR_error_string(ERR_get_error(), NULL));
                SSL_CTX_free(mtls->internals->ssl_ctx);
                free(mtls->internals);
                mtls->internals = NULL;
                return TLS_EFILE;
            }
        }
        mtls->have_trust_file = 1;
    }
    if (sha256_fingerprint && !no_certcheck)
    {
        memcpy(mtls->fingerprint, sha256_fingerprint, 32);
        mtls->have_sha256_fingerprint = 1;
    }
    if (!(mtls->internals->ssl = SSL_new(mtls->internals->ssl_ctx)))
    {
        *errstr = xasprintf(_("cannot create a TLS structure: %s"),
                ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(mtls->internals->ssl_ctx);
        free(mtls->internals);
        mtls->internals = NULL;
        return TLS_ELIBFAILED;
    }
    mtls->no_certcheck = no_certcheck;
    mtls->hostname = xstrdup(hostname);
    int index = SSL_get_ex_new_index(0, "mtls", NULL, NULL, NULL);
    assert(1 == index);
    SSL_set_ex_data(mtls->internals->ssl, index, mtls);
    SSL_set_tlsext_host_name(mtls->internals->ssl, mtls->hostname);

    //X509_V_ERR_HOSTNAME_MISMATCH
    //SSL_set_verify(mtls->internals->ssl, SSL_VERIFY_PEER, NULL);
    SSL_set_verify(mtls->internals->ssl, no_certcheck ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);// ssl_check_cert);
    // SSL_get_verify_result returns X509_V_OK for some reason
    /* Enable automatic hostname checks */
    param = SSL_get0_param(mtls->internals->ssl);
    // has no effect??
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT | X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    int success = X509_VERIFY_PARAM_set1_host(param, mtls->hostname, 0);
    assert(success);
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
    //SSL_CTX_set1_param(mtls->internals->ssl_ctx, param);
//    SSL_set_param
    SSL_set_verify(mtls->internals->ssl, SSL_VERIFY_NONE, NULL);
    return TLS_EOK;
}


/*
 * openssl_io_error()
 *
 * Used only internally by the OpenSSL code.
 *
 * Construct an error line according to 'error_code' (which originates from an
 * SSL_read(), SSL_write() or SSL_connect() operation) and 'error_code2' (which
 * originates from an SSL_get_error() call with 'error_code' as its argument).
 * The line will read: "error_string: error_reason". 'error_string' is given by
 * the calling function, this function finds out 'error_reason'.
 * The resulting string will be returned in an allocated string.
 * OpenSSL error strings are max 120 characters long according to
 * ERR_error_string(3).
 */

static char *openssl_io_error(int error_code, int error_code2,
        const char *error_string)
{
    unsigned long error_code3;
    const char *error_reason;

    switch (error_code2)
    {
        case SSL_ERROR_SYSCALL:
            error_code3 = ERR_get_error();
            if (error_code3 == 0)
            {
                if (error_code == 0)
                {
                    error_reason = _("a protocol violating EOF occurred");
                }
                else if (error_code == -1)
                {
                    error_reason = strerror(errno);
                }
                else
                {
                    error_reason = _("unknown error");
                }
            }
            else
            {
                error_reason = ERR_error_string(error_code3, NULL);
            }
            break;

        case SSL_ERROR_ZERO_RETURN:
            error_reason = _("the connection was closed unexpectedly");
            break;

        case SSL_ERROR_SSL:
            error_reason = ERR_error_string(ERR_get_error(), NULL);
            break;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            error_reason = _("the operation timed out");
            break;

        default:
            /* probably SSL_ERROR_NONE */
            error_reason = _("unknown error");
            break;
    }
    return xasprintf("%s: %s", error_string, error_reason);
}


/*
 * mtls_start()
 *
 * see mtls.h
 */

int mtls_start(mtls_t *mtls, int fd,
        mtls_cert_info_t *tci, char **mtls_parameter_description, char **errstr)
{
    int error_code;

    if (!SSL_set_fd(mtls->internals->ssl, fd))
    {
        *errstr = xasprintf(_("cannot set the file descriptor for TLS: %s"),
                ERR_error_string(ERR_get_error(), NULL));
        SSL_free(mtls->internals->ssl);
        SSL_CTX_free(mtls->internals->ssl_ctx);
        return TLS_ELIBFAILED;
    }
    if ((error_code = SSL_connect(mtls->internals->ssl)) < 1)
    {
        if (errno == EINTR
                && (SSL_get_error(mtls->internals->ssl, error_code) == SSL_ERROR_WANT_READ
                    || SSL_get_error(mtls->internals->ssl, error_code)
                    == SSL_ERROR_WANT_WRITE))
        {
            *errstr = xasprintf(_("operation aborted"));
        }
        else
        {
            *errstr = openssl_io_error(error_code,
                    SSL_get_error(mtls->internals->ssl, error_code),
                    _("TLS handshake failed"));
        }
        SSL_free(mtls->internals->ssl);
        SSL_CTX_free(mtls->internals->ssl_ctx);
        return TLS_EIO;
    }
    if (tci)
    {
        if ((error_code = mtls_cert_info_get(mtls, tci, errstr)) != TLS_EOK)
        {
            SSL_free(mtls->internals->ssl);
            SSL_CTX_free(mtls->internals->ssl_ctx);
            return error_code;
        }
    }
    if (mtls_parameter_description)
    {
        static const int desc_size = 200;
        *mtls_parameter_description = xmalloc(desc_size);
        const SSL_CIPHER* cipher = SSL_get_current_cipher(mtls->internals->ssl);
        const char* name = SSL_CIPHER_standard_name(cipher);
        if (isatty(fileno(stdout)))
            snprintf(*mtls_parameter_description, desc_size, "%s \x1B]8;;https://ciphersuite.info/cs/%s/\x1b\\%s\x1b]8;;\x1b\\", SSL_CIPHER_get_version(cipher), name, name);
        else
            snprintf(*mtls_parameter_description, desc_size, "%s %s", SSL_CIPHER_get_version(cipher), name);
    }
    if (!mtls->no_certcheck)
    {
        if ((error_code = mtls_check_cert(mtls, errstr)) != TLS_EOK)
        {
            SSL_free(mtls->internals->ssl);
            SSL_CTX_free(mtls->internals->ssl_ctx);
            return error_code;
        }
    }
    mtls->is_active = 1;
    mtls->is_tls_1_3_or_newer =
        SSL_SESSION_get_protocol_version(SSL_get_session(mtls->internals->ssl)) >= TLS1_3_VERSION;
    return TLS_EOK;
}


/*
 * mtls_readbuf_read()
 *
 * Wraps TLS read function to provide buffering for mtls_gets().
 */

int mtls_readbuf_read(mtls_t *mtls, readbuf_t *readbuf, char *ptr,
        char **errstr)
{
    int ret;
    int error_code;

    if (readbuf->count <= 0)
    {
        ret = SSL_read(mtls->internals->ssl, readbuf->buf, sizeof(readbuf->buf));
        if (ret < 1)
        {
            if ((error_code = SSL_get_error(mtls->internals->ssl, ret)) == SSL_ERROR_NONE)
            {
                return 0;
            }
            else
            {
                if (errno == EINTR
                        && (SSL_get_error(mtls->internals->ssl, ret) == SSL_ERROR_WANT_READ
                            || SSL_get_error(mtls->internals->ssl, ret)
                            == SSL_ERROR_WANT_WRITE))
                {
                    *errstr = xasprintf(_("operation aborted"));
                }
                else
                {
                    *errstr = openssl_io_error(ret, error_code,
                            _("cannot read from TLS connection"));
                }
                return TLS_EIO;
            }
        }
        readbuf->count = ret;
        readbuf->ptr = readbuf->buf;
    }
    readbuf->count--;
    *ptr = *((readbuf->ptr)++);
    return 1;
}


/*
 * mtls_puts()
 *
 * see mtls.h
 */

int mtls_puts(mtls_t *mtls, const char *s, size_t len, char **errstr)
{
    int error_code;

    if (len < 1)
    {
        /* nothing to be done */
        return TLS_EOK;
    }

    if ((error_code = SSL_write(mtls->internals->ssl, s, (int)len)) != (int)len)
    {
        if (errno == EINTR
                && ((SSL_get_error(mtls->internals->ssl, error_code) == SSL_ERROR_WANT_READ
                        || SSL_get_error(mtls->internals->ssl, error_code)
                        == SSL_ERROR_WANT_WRITE)))
        {
            *errstr = xasprintf(_("operation aborted"));
        }
        else
        {
            *errstr = openssl_io_error(error_code,
                    SSL_get_error(mtls->internals->ssl, error_code),
                    _("cannot write to TLS connection"));
        }
        return TLS_EIO;
    }

    return TLS_EOK;
}


/*
 * mtls_close()
 *
 * see mtls.h
 */

void mtls_close(mtls_t *mtls)
{
    if (mtls->is_active)
    {
        SSL_shutdown(mtls->internals->ssl);
        SSL_free(mtls->internals->ssl);
        SSL_CTX_free(mtls->internals->ssl_ctx);
    }
    free(mtls->internals);
    mtls->internals = NULL;
    if (mtls->hostname)
    {
        free(mtls->hostname);
    }
    mtls_clear(mtls);
}


/*
 * mtls_lib_deinit()
 *
 * see mtls.h
 */

void mtls_lib_deinit(void)
{
}
