/**
 * @file	Key.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	Key
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "Key.hpp"

#include <stdio.h>
#include <stdlib.h>

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include <openssl/err.h>
#include <openssl/x509.h>
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
#include <mbedtls/pk.h>
#endif

namespace signedsecurefile {

	Key::Key()
	{
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		ossl_rsa = NULL;
		ossl_ec = NULL;
		ossl_err = 0;
		ossl_autofree = false;
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
		mbed_ec = NULL;
		mbed_rsa = NULL;
		mbed_err = 0;
#endif
	}

	Key::~Key()
	{
		cleanupKeys();
	}

	void Key::cleanupKeys()
	{
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		opensslCleanup();
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
		mbedCleanup();
#endif
	}

#if defined(HAS_OPENSSL) && HAS_OPENSSL
	void Key::opensslCleanup()
	{
		if (this->ossl_autofree)
		{
			if (this->ossl_rsa)
			{
				RSA_free(this->ossl_rsa);
				this->ossl_rsa = NULL;
			}
			if (this->ossl_ec)
			{
				EC_KEY_free(this->ossl_ec);
				this->ossl_ec = NULL;
			}
		}
	}
#endif

#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
	void Key::mbedCleanup()
	{
		if (this->mbed_ec)
		{
			mbedtls_ecp_keypair_free(this->mbed_ec);
			free(this->mbed_ec);
			this->mbed_ec = NULL;
		}
		if (this->mbed_rsa)
		{
			mbedtls_rsa_free(this->mbed_rsa);
			free(this->mbed_rsa);
			this->mbed_rsa = NULL;
		}
	}

	void Key::setMbedtlsRSAKey(mbedtls_rsa_context *rsa)
	{
		cleanupKeys();
		this->mbed_rsa = (mbedtls_rsa_context*)malloc(sizeof(mbedtls_rsa_context));
		mbedtls_rsa_init(this->mbed_rsa, MBEDTLS_RSA_PKCS_V15, 0);
		mbedtls_rsa_copy(this->mbed_rsa, rsa);
	}
	void Key::setMbedtlsECKey(mbedtls_ecp_keypair *ec)
	{
		cleanupKeys();
		this->mbed_ec = (mbedtls_ecp_keypair*)malloc(sizeof(mbedtls_ecp_keypair));
		mbedtls_ecp_group_init(&this->mbed_ec->grp);
		mbedtls_mpi_init(&this->mbed_ec->d);
		mbedtls_ecp_point_init(&this->mbed_ec->Q);
		mbedtls_ecp_group_copy(&this->mbed_ec->grp, &ec->grp);
		mbedtls_mpi_copy(&this->mbed_ec->d, &ec->d);
		mbedtls_ecp_copy(&this->mbed_ec->Q, &ec->Q);
	}

	bool Key::setPublicKey(const unsigned char *key, int length)
	{
		bool retval = false;
		int librc;
		mbedtls_pk_context pk_ctx;
		mbedtls_pk_init(&pk_ctx);
		librc = mbedtls_pk_parse_public_key(&pk_ctx, key, length);
		if (librc != 0)
		{
			goto cleanup;
		}
		switch (mbedtls_pk_get_type(&pk_ctx))
		{
		case MBEDTLS_PK_RSA:
		case MBEDTLS_PK_RSA_ALT:
		case MBEDTLS_PK_RSASSA_PSS:
			setMbedtlsRSAKey(mbedtls_pk_rsa(pk_ctx));
			retval = true;
			break;
		case MBEDTLS_PK_ECKEY:
		case MBEDTLS_PK_ECKEY_DH:
		case MBEDTLS_PK_ECDSA:
			setMbedtlsECKey(mbedtls_pk_ec(pk_ctx));
			retval = true;
			break;
		}

	cleanup:
		mbedtls_pk_free(&pk_ctx);
		return retval;
	}
	bool Key::setPrivateKey(const unsigned char *key, int length)
	{
		bool retval = false;
		int librc;
		mbedtls_pk_context pk_ctx;
		mbedtls_pk_init(&pk_ctx);
		librc = mbedtls_pk_parse_key(&pk_ctx, key, length, NULL, 0);
		if (librc != 0)
		{
			goto cleanup;
		}
		switch (mbedtls_pk_get_type(&pk_ctx))
		{
		case MBEDTLS_PK_RSA:
		case MBEDTLS_PK_RSA_ALT:
		case MBEDTLS_PK_RSASSA_PSS:
			setMbedtlsRSAKey(mbedtls_pk_rsa(pk_ctx));
			retval = true;
			break;
		case MBEDTLS_PK_ECKEY:
		case MBEDTLS_PK_ECKEY_DH:
		case MBEDTLS_PK_ECDSA:
			setMbedtlsECKey(mbedtls_pk_ec(pk_ctx));
			retval = true;
			break;
		}

	cleanup:
		mbedtls_pk_free(&pk_ctx);
		return retval;
	}
#endif

	bool Key::setRSAPublicKey(const unsigned char *key, int length)
	{
		const unsigned char *pkey = key;
		cleanupKeys();
#if defined(SIGNEDSECUREFILE_USE_MBEDTLS) && SIGNEDSECUREFILE_USE_MBEDTLS
		return setPublicKey(key, length);
#elif defined(SIGNEDSECUREFILE_USE_OPENSSL) && SIGNEDSECUREFILE_USE_OPENSSL
		if (!(this->ossl_rsa = d2i_RSA_PUBKEY(NULL, &pkey, length)))
		{
			ossl_err = ERR_get_error();
			return false;
		}
		ossl_autofree = false;
		return true;
#else
		return false;
#endif
	}

	bool Key::setRSAPrivateKey(const unsigned char *key, int length)
	{
		const unsigned char *pkey = key;
		cleanupKeys();
#if defined(SIGNEDSECUREFILE_USE_MBEDTLS) && SIGNEDSECUREFILE_USE_MBEDTLS
		return setPrivateKey(key, length);
#elif defined(SIGNEDSECUREFILE_USE_OPENSSL) && SIGNEDSECUREFILE_USE_OPENSSL
		if (!(this->ossl_rsa = d2i_RSAPrivateKey(NULL, &pkey, length)))
		{
			ossl_err = ERR_get_error();
			return false;
		}
		ossl_autofree = false;
		return true;
#else
		return false;
#endif
	}

	bool Key::setECPublicKey(const unsigned char *key, int length)
	{
		const unsigned char *pkey = key;
		cleanupKeys();
#if defined(SIGNEDSECUREFILE_USE_MBEDTLS) && SIGNEDSECUREFILE_USE_MBEDTLS
		return setPublicKey(key, length);
#elif defined(SIGNEDSECUREFILE_USE_OPENSSL) && SIGNEDSECUREFILE_USE_OPENSSL
		if (!(this->ossl_ec = d2i_EC_PUBKEY(NULL, &pkey, length)))
		{
			ossl_err = ERR_get_error();
			return false;
		}
		ossl_autofree = false;
		return true;
#else
		return false;
#endif
	}

	bool Key::setECPrivateKey(const unsigned char *key, int length)
	{
		const unsigned char *pkey = key;
		cleanupKeys();
#if defined(SIGNEDSECUREFILE_USE_MBEDTLS) && SIGNEDSECUREFILE_USE_MBEDTLS
		return setPrivateKey(key, length);
#elif defined(SIGNEDSECUREFILE_USE_OPENSSL) && SIGNEDSECUREFILE_USE_OPENSSL
		if (!(this->ossl_rsa = d2i_RSAPrivateKey(NULL, &pkey, length)))
		{
			ossl_err = ERR_get_error();
			return false;
		}
		ossl_autofree = false;
		return true;
#else
		return false;
#endif
	}
}
