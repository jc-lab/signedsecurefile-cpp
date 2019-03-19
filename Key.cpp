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

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include <openssl/err.h>
#include <openssl/x509.h>
#endif

namespace signedsecurefile {

	Key::Key()
	{
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		rsa = NULL;
		ec = NULL;
		ossl_err = 0;
		autofree = false;
#endif
	}

	Key::~Key()
	{
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		opensslCleanup();
#endif
	}

#if defined(HAS_OPENSSL) && HAS_OPENSSL
	void Key::opensslCleanup()
	{
		if (this->autofree)
		{
			if (this->rsa)
			{
				RSA_free(this->rsa);
				this->rsa = NULL;
			}
		}
	}

	bool Key::setRSAPublicKey(const unsigned char *key, int length)
	{
		const unsigned char *pkey = key;
		opensslCleanup();
		if (!(this->rsa = d2i_RSA_PUBKEY(NULL, &pkey, length)))
		{
			ossl_err = ERR_get_error();
			return false;
		}
		autofree = false;
		return true;
	}

	bool Key::setRSAPrivateKey(const unsigned char *key, int length)
	{
		const unsigned char *pkey = key;
		opensslCleanup();
		if (!(this->rsa = d2i_RSAPrivateKey(NULL, &pkey, length)))
		{
			ossl_err = ERR_get_error();
			return false;
		}
		autofree = false;
		return true;
	}

	bool Key::setECPublicKey(const unsigned char *key, int length)
	{
		const unsigned char *pkey = key;
		opensslCleanup();
		if (!(this->ec = d2i_EC_PUBKEY(NULL, &pkey, length)))
		{
			ossl_err = ERR_get_error();
			return false;
		}
		autofree = false;
		return true;
	}

	bool Key::setECPrivateKey(const unsigned char *key, int length)
	{
		const unsigned char *pkey = key;
		opensslCleanup();
		if (!(this->rsa = d2i_RSAPrivateKey(NULL, &pkey, length)))
		{
			ossl_err = ERR_get_error();
			return false;
		}
		autofree = false;
		return true;
	}
#endif
}
