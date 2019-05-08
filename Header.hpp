/**
 * @file	Header.h
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	Header
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <string>

#include "AbstructSignedSecureFile.hpp"
#include "exception/SignedSecureFileException.hpp"

#include "Key.hpp"
#include "Buffer.hpp"

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include <openssl/ec.h>
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#endif

namespace signedsecurefile {

	class HeaderCipherAlgorithm
	{
	private:
		int value;
		std::string algoName;

	public:
		HeaderCipherAlgorithm();
		HeaderCipherAlgorithm(int value, const char *algoNamealgoName);

	public:
		static HeaderCipherAlgorithm NONE;
		static HeaderCipherAlgorithm V1_RSA;
		static HeaderCipherAlgorithm EC;
		static HeaderCipherAlgorithm RSA;

		int getValue() const { return this->value; }
		std::string getAlgoName() const { return this->algoName; }

		bool operator==(const HeaderCipherAlgorithm &target) const {
			return target.value == this->value;
		}
	};

	class DataCipherAlgorithm
	{
	private:
		int value;
		std::string algoName;

	public:
		DataCipherAlgorithm();
		DataCipherAlgorithm(int value, const char *algoName);

	public:
		static DataCipherAlgorithm NONE;
		static DataCipherAlgorithm AES;

		int getValue() const { return this->value; }
		std::string getAlgoName() const { return this->algoName; }

		bool operator==(const DataCipherAlgorithm &target) const {
			return target.value == this->value;
		}
	};

	class Header : public AbstructSignedSecureFile
	{
	public:
		static int COMMON_HEADER_SIZE;
		static unsigned char DATA_IV[16];

	private:
#pragma pack(push, 1)

		static int SECURE_HEADER_SIZE;
		static int VERSION;
		static unsigned char SIGNATURE[15];

		typedef struct _tag_SecureHeader {
			uint8_t sig[16]; // 16
			uint8_t key[32]; // 32
			uint8_t hmac[32]; // 32
			uint32_t datasize; // 4
		} SecureHeader_t;

		typedef struct _tag_RawHeader {
			uint8_t signature[15];
			uint8_t version;
			uint8_t headerCipherAlgorithm;
			uint8_t dataCipherAlgorithm;
			uint16_t signedSecureHeaderSize;
			uint32_t keySize; // 4 bytes
			uint8_t rev1[8]; // 8 bytes
		} RawHeader_t;

		typedef struct _tag_ECSignedSecureHeader {
			uint16_t privKeySize;
			uint8_t  sigSize;
			uint8_t  privKey[1];
		} ECSignedSecureHeader_t;
#pragma pack(pop)

		bool _sysIsLitleEndian;

		RawHeader_t rawHeader;
		bool rawHeaderReaded;

		HeaderCipherAlgorithm headerCipherAlgorithm;
		DataCipherAlgorithm dataCipherAlgorithm;

		Key *asymKey;
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		EC_KEY *ecLocalPrivateKey;
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
		mbedtls_entropy_context entropy_ctx;
		mbedtls_ctr_drbg_context ctr_drbg_ctx;
#endif

		ECSignedSecureHeader_t *ecSignedSecureHeader;
		size_t outputSignedSecureHeaderTotalSize;
		size_t outputSignedSecureHeaderDataSize;

		void int32toArray(unsigned char *buffer, uint32_t value);
		void arrayToInt32(const unsigned char *buffer, uint32_t *value);
		void int16toArray(unsigned char *buffer, uint16_t value);
		void arrayToInt16(const unsigned char *buffer, uint16_t *value);

		HeaderCipherAlgorithm findHeaderCipherAlgorithm(unsigned char value);
		DataCipherAlgorithm findDataCipherAlgorithm(unsigned char value);

		void commonConstructor();

	public:
		SecureHeader_t secureHeader;

		Header();
		Header(const AbstructSignedSecureFile *parent);
		virtual ~Header();
		void setAsymKey(Key *key, bool encMode = false);
		Key *getAsymKey() const { return asymKey; }

		void initHeader();
		void generateKey();
		void setHeaderCipherAlgorithm(HeaderCipherAlgorithm headerCipherAlgorithm);
		void setDataCipherAlgorithm(DataCipherAlgorithm dataCipherAlgorithm);
		DataCipherAlgorithm getDataCipherAlgorithm() { return this->dataCipherAlgorithm; }
		
		int getHeaderLength() const;
		int getSignedSecureHeaderSize();

		// -1 : error
		// 0 : reading
		// 1 : done
		int readBuffer(Buffer &buffer, exception::SignedSecureFileException *exception = NULL);
		bool writeTo(Buffer &buffer, size_t computedHeaderSize, exception::SignedSecureFileException *exception = NULL);
	};

}
