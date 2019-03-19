/**
 * @file	Key.h
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	Key
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include <openssl/rsa.h>
#include <openssl/ec.h>
#endif

namespace signedsecurefile {

	class Key
	{
	private:
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		RSA *rsa;
		EC_KEY *ec;
		bool autofree;
		unsigned long ossl_err;

		void opensslCleanup();

	public:
		unsigned long getOpensslError() { return this->ossl_err; }
		bool isRSAKey() { return this->rsa != NULL; }
		bool isECKey() { return this->ec != NULL; }
		RSA *getOpensslRSAKey() { return this->rsa; }
		EC_KEY *getOpensslECKey() { return this->ec; }
		void setOpensslRSAKey(RSA *rsa, bool autofree = false) {
			opensslCleanup();
			this->rsa = rsa;
			this->autofree = autofree;
		}
		void setOpensslECKey(EC_KEY *ec, bool autofree = false) {
			opensslCleanup();
			this->ec = ec;
			this->autofree = autofree;
		}
#endif

	public:
		Key();
		virtual ~Key();

		bool setRSAPublicKey(const unsigned char *key, int length);
		bool setRSAPrivateKey(const unsigned char *key, int length);
		bool setECPublicKey(const unsigned char *key, int length);
		bool setECPrivateKey(const unsigned char *key, int length);
	};

}

