/**
 * @file	Key.h
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	Key
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

//#define SIGNEDSECUREFILE_USE_OPENSSL 1

#if !defined(SIGNEDSECUREFILE_USE_OPENSSL) && !defined(SIGNEDSECUREFILE_USE_MBEDTLS)
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
#define SIGNEDSECUREFILE_USE_MBEDTLS 1
#elif defined(HAS_OPENSSL) && HAS_OPENSSL
#define SIGNEDSECUREFILE_USE_OPENSSL 1
#endif
#endif

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include <openssl/rsa.h>
#include <openssl/ec.h>
#endif

#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#endif

namespace signedsecurefile {

	class Key
	{
	private:
		void cleanupKeys();

#if defined(HAS_OPENSSL) && HAS_OPENSSL
	private:
		RSA *ossl_rsa;
		EC_KEY *ossl_ec;
		bool ossl_autofree;
		unsigned long ossl_err;

		void opensslCleanup();

	public:
		unsigned long getOpensslError() { return this->ossl_err; }
		RSA *getOpensslRSAKey() { return this->ossl_rsa; }
		EC_KEY *getOpensslECKey() { return this->ossl_ec; }
		void setOpensslRSAKey(RSA *rsa, bool autofree = false) {
			cleanupKeys();
			this->ossl_rsa = rsa;
			this->ossl_autofree = autofree;
		}
		void setOpensslECKey(EC_KEY *ec, bool autofree = false) {
			cleanupKeys();
			this->ossl_ec = ec;
			this->ossl_autofree = autofree;
		}
		bool isOpensslKey() const {
			return ossl_rsa || ossl_ec;
		}
#endif

#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
	private:
		mbedtls_ecp_keypair *mbed_ec;
		mbedtls_rsa_context *mbed_rsa;
		unsigned long mbed_err;

		void mbedCleanup();

	public:
		unsigned long getMbedtlsError() { return this->mbed_err; }
		const mbedtls_rsa_context *getMbedtlsRSAKey() { return this->mbed_rsa; }
		const mbedtls_ecp_keypair *getMbedtlsECKey() { return this->mbed_ec; }
		void setMbedtlsRSAKey(mbedtls_rsa_context *rsa);
		void setMbedtlsECKey(mbedtls_ecp_keypair *ec);
		bool isMbedtlsKey() const {
			return mbed_rsa || mbed_ec;
		}

		bool setPublicKey(const unsigned char *key, int length);
		bool setPrivateKey(const unsigned char *key, int length);
#endif

	public:
		Key();
		virtual ~Key();

		bool isRSAKey() {
			bool result = false;
#if defined(HAS_OPENSSL) && HAS_OPENSSL
			result = result || (this->ossl_rsa != NULL);
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
			result = result || (this->mbed_rsa != NULL);
#endif
			return result;
		}

		bool isECKey() {
			bool result = false;
#if defined(HAS_OPENSSL) && HAS_OPENSSL
			result = result || (this->ossl_ec != NULL);
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
			result = result || (this->mbed_ec != NULL);
#endif
			return result;
		}

		bool setRSAPublicKey(const unsigned char *key, int length);
		bool setRSAPrivateKey(const unsigned char *key, int length);
		bool setECPublicKey(const unsigned char *key, int length);
		bool setECPrivateKey(const unsigned char *key, int length);
	};

}

