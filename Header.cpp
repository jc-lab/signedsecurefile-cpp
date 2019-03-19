/**
 * @file	Header.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	Header
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "Header.hpp"

#include "exception/SignedSecureFileException.hpp"
#include "exception/InvalidFileException.hpp"
#include "exception/InvalidKeyException.hpp"
#include "exception/IntegrityException.hpp"

#ifdef HAS_OPENSSL
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

namespace signedsecurefile {

	HeaderCipherAlgorithm HeaderCipherAlgorithm::NONE(0, "NONE");
	HeaderCipherAlgorithm HeaderCipherAlgorithm::V1_RSA(1, "RSA");
	HeaderCipherAlgorithm HeaderCipherAlgorithm::EC(2, "EC");
	HeaderCipherAlgorithm HeaderCipherAlgorithm::RSA(3, "RSA");
	DataCipherAlgorithm DataCipherAlgorithm::NONE(0, "NONE");
	DataCipherAlgorithm DataCipherAlgorithm::AES(1, "AES/CBC/PKCS5Pading");

	unsigned char Header::DATA_IV[] = { 0x92, 0xe5, 0x26, 0x21, 0x1e, 0xda, 0xca, 0x0f, 0x89, 0x5f, 0x2b, 0x74, 0xc1, 0xc4, 0xb4, 0xb9 };

	int Header::COMMON_HEADER_SIZE = 32;
	int Header::SECURE_HEADER_SIZE = 84;
	int Header::VERSION = 2;
	unsigned char Header::SIGNATURE[] = { 0x0a, 0x9b, 0xd8, 0x13, 0x97, 0x1f, 0x93, 0xe8, 0x6b, 0x7e, 0xdf, 0x05, 0x70, 0x54, 0x02 };

	HeaderCipherAlgorithm::HeaderCipherAlgorithm()
	{
		this->value = 0;
	}
	HeaderCipherAlgorithm::HeaderCipherAlgorithm(int value, const char *algoName)
	{
		this->value = value;
		this->algoName = algoName;
	}
	DataCipherAlgorithm::DataCipherAlgorithm()
	{
		this->value = 0;
	}
	DataCipherAlgorithm::DataCipherAlgorithm(int value, const char *algoName)
	{
		this->value = value;
		this->algoName = algoName;
	}

	void Header::commonConstructor()
	{
		volatile uint32_t testValue = 0x11223344;
		const uint8_t *ptestFirst = (const uint8_t*)&testValue;
		_sysIsLitleEndian = (*ptestFirst == 0x44);
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		ecLocalPrivateKey = NULL;
#endif
		ecSignedSecureHeader = NULL;
		initHeader();
	}

	Header::Header()
	{
		commonConstructor();
	}

	Header::Header(const AbstructSignedSecureFile *parent)
	{
		AbstructSignedSecureFile::setParent(parent);
		commonConstructor();
	}
	
	Header::~Header()
	{
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		if (ecLocalPrivateKey)
		{
			EC_KEY_free(ecLocalPrivateKey);
		}
#endif
		if (ecSignedSecureHeader)
		{
			getMemoryAllocator()->release(ecSignedSecureHeader);
		}
	}

	void Header::setAsymKey(Key *key, bool encMode)
	{
		this->asymKey = key;
		if (ecSignedSecureHeader)
		{
			getMemoryAllocator()->release(ecSignedSecureHeader);
			ecSignedSecureHeader = NULL;
		}
		if (key) {
			if (key->isRSAKey())
			{
				setHeaderCipherAlgorithm(HeaderCipherAlgorithm::RSA);
				this->outputSignedSecureHeaderTotalSize = RSA_size(key->getOpensslRSAKey());
			}
			else if (key->isECKey())
			{
				setHeaderCipherAlgorithm(HeaderCipherAlgorithm::EC);

				if (encMode)
				{
					EC_KEY *ecKey = this->asymKey->getOpensslECKey();
					int signatureSize = ECDSA_size(this->asymKey->getOpensslECKey());
					unsigned char prefixHeader[3];
					size_t encodedSecureHeaderSize = sizeof(secureHeader);

					BIO *privateKeyBio = NULL;
					EVP_PKEY *pkey = NULL;
					PKCS8_PRIV_KEY_INFO *p8ki = NULL;

					do {
						BUF_MEM *bptr = NULL;

						ecLocalPrivateKey = EC_KEY_new();
						EC_KEY_set_group(ecLocalPrivateKey, EC_KEY_get0_group(ecKey));
						EC_KEY_generate_key(ecLocalPrivateKey);

						privateKeyBio = BIO_new(BIO_s_mem());
						if (!privateKeyBio)
						{
							break;
						}

						EVP_PKEY *pkey = EVP_PKEY_new();
						if (!pkey)
						{
							break;
						}
						EVP_PKEY_set1_EC_KEY(pkey, ecLocalPrivateKey);
						PKCS8_PRIV_KEY_INFO *p8ki = EVP_PKEY2PKCS8(pkey);
						if (!p8ki)
						{
							break;
						}
						if (i2d_PKCS8_PRIV_KEY_INFO_bio(privateKeyBio, p8ki) <= 0)
						{
							break;
						}

						BIO_get_mem_ptr(privateKeyBio, &bptr);

						ecSignedSecureHeader = (ECSignedSecureHeader_t*)getMemoryAllocator()->allocate(3 + bptr->length + signatureSize);
						ecSignedSecureHeader->privKeySize = bptr->length;
						ecSignedSecureHeader->sigSize = signatureSize;
						memcpy(ecSignedSecureHeader->privKey, bptr->data, bptr->length);
						outputSignedSecureHeaderTotalSize = 3 + ecSignedSecureHeader->privKeySize + ecSignedSecureHeader->sigSize;
					} while (0);

					if (p8ki) {
						PKCS8_PRIV_KEY_INFO_free(p8ki);
					}
					if (pkey) {
						EVP_PKEY_free(pkey);
					}
					if (privateKeyBio) {
						BIO_free_all(privateKeyBio);
					}

					encodedSecureHeaderSize += 1;
					if (encodedSecureHeaderSize % 16)
					{
						encodedSecureHeaderSize += 16 - (encodedSecureHeaderSize % 16);
					}
					this->outputSignedSecureHeaderDataSize = encodedSecureHeaderSize;
					this->outputSignedSecureHeaderTotalSize += encodedSecureHeaderSize;
				}
			}
		}
		rawHeader.signedSecureHeaderSize = this->outputSignedSecureHeaderTotalSize;
	}

	void Header::initHeader()
	{
		int i;
		memset(&secureHeader, 0, sizeof(secureHeader));
		for (i = 0; i < sizeof(rawHeader); i++)
			((char*)&rawHeader)[i] = 0;
		for (i = 0; i < 15; i++)
			rawHeader.signature[i] = SIGNATURE[i];
		for (i = 0; i < 15; i++)
			secureHeader.sig[i] = SIGNATURE[i];
		rawHeader.version = VERSION;
		secureHeader.sig[15] = VERSION;
		rawHeaderReaded = false;
		asymKey = NULL;
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		if (ecLocalPrivateKey)
		{
			EC_KEY_free(ecLocalPrivateKey);
			ecLocalPrivateKey = NULL;
		}
#endif
	}

	void Header::generateKey()
	{
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		RAND_bytes(secureHeader.key, sizeof(secureHeader.key));
#endif
	}

	void Header::setHeaderCipherAlgorithm(HeaderCipherAlgorithm headerCipherAlgorithm)
	{
		this->headerCipherAlgorithm = headerCipherAlgorithm;
		rawHeader.headerCipherAlgorithm = (uint8_t)headerCipherAlgorithm.getValue();
	}
	void Header::setDataCipherAlgorithm(DataCipherAlgorithm dataCipherAlgorithm)
	{
		this->dataCipherAlgorithm = dataCipherAlgorithm;
		rawHeader.dataCipherAlgorithm = (uint8_t)dataCipherAlgorithm.getValue();
	}

	HeaderCipherAlgorithm Header::findHeaderCipherAlgorithm(unsigned char value)
	{
		static const HeaderCipherAlgorithm *list[] = { &HeaderCipherAlgorithm::NONE, &HeaderCipherAlgorithm::V1_RSA, &HeaderCipherAlgorithm::EC, &HeaderCipherAlgorithm::RSA, NULL};
		for (const HeaderCipherAlgorithm **pitem = list; *pitem; pitem++)
		{
			if ((*pitem)->getValue() == value)
			{
				return **pitem;
			}
		}
		return HeaderCipherAlgorithm::NONE;
	}

	DataCipherAlgorithm Header::findDataCipherAlgorithm(unsigned char value)
	{
		static const DataCipherAlgorithm *list[] = { &DataCipherAlgorithm::NONE, &DataCipherAlgorithm::AES, NULL };
		for (const DataCipherAlgorithm **pitem = list; *pitem; pitem++)
		{
			if ((*pitem)->getValue() == value)
			{
				return **pitem;
			}
		}
		return DataCipherAlgorithm::NONE;
	}

	int Header::getHeaderLength() const
	{
		return sizeof(rawHeader) + rawHeader.keySize / 8;
	}

	int Header::getSignedSecureHeaderSize()
	{
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		if (headerCipherAlgorithm == HeaderCipherAlgorithm::RSA)
		{
			return RSA_size(this->asymKey->getOpensslRSAKey());
		}else if (headerCipherAlgorithm == HeaderCipherAlgorithm::EC)
		{
			return this->outputSignedSecureHeaderTotalSize;
		}
		return -1;
#endif
	}

	int Header::readBuffer(Buffer &buffer, exception::SignedSecureFileException *exception)
	{
		if (!rawHeaderReaded)
		{
			if (buffer.readRemaining() < COMMON_HEADER_SIZE)
				return 1;
			buffer.read((unsigned char*)&rawHeader, COMMON_HEADER_SIZE);
			if (!_sysIsLitleEndian)
			{
				RawHeader_t *bufHeader = (RawHeader_t *)&rawHeader;
				int16toArray((unsigned char*)&bufHeader->signedSecureHeaderSize, bufHeader->signedSecureHeaderSize);
				int32toArray((unsigned char*)&bufHeader->keySize, bufHeader->keySize);
			}

			if (memcmp(rawHeader.signature, SIGNATURE, sizeof(SIGNATURE)))
			{
				exception::InvalidFileException invalidFileException("file error");
				if (exception)
					*exception = invalidFileException;
				if (getUseCppThrow())
					throw invalidFileException;
			}

			if (rawHeader.version < 2 || rawHeader.version > VERSION)
			{
				exception::InvalidFileException invalidFileException("version mismatch");
				if (exception)
					*exception = invalidFileException;
				if (getUseCppThrow())
					throw invalidFileException;
			}

			this->headerCipherAlgorithm = findHeaderCipherAlgorithm(rawHeader.headerCipherAlgorithm);
			this->dataCipherAlgorithm = findDataCipherAlgorithm(rawHeader.dataCipherAlgorithm);

			if ((this->headerCipherAlgorithm == HeaderCipherAlgorithm::NONE) || (this->dataCipherAlgorithm == DataCipherAlgorithm::NONE))
			{
				exception::InvalidFileException invalidFileException("not support algorithm");
				if (exception)
					*exception = invalidFileException;
				if (getUseCppThrow())
					throw invalidFileException;
			}

			rawHeaderReaded = true;
		}
		if (rawHeaderReaded)
		{
			if (buffer.readRemaining() > rawHeader.signedSecureHeaderSize)
			{
				bool result = false;
				exception::SignedSecureFileException causedException;
				unsigned char *signedSecureHeader = (unsigned char *)getMemoryAllocator()->allocate(rawHeader.signedSecureHeaderSize);
				unsigned char *tempSecretKey = NULL;
				unsigned char *decodedSecureHeader = NULL;
				unsigned char sharedKey[32];
				EC_KEY *ecPrivateKey = NULL;
				EC_GROUP *ecPrivateGroup = NULL;
				ECDSA_SIG *ecsig = NULL;
				int orc;
				buffer.read(signedSecureHeader, rawHeader.signedSecureHeaderSize);
				do {
#if defined(HAS_OPENSSL) && HAS_OPENSSL
					if (this->headerCipherAlgorithm == HeaderCipherAlgorithm::EC)
					{
						uint16_t ecKeySize = (((uint16_t)signedSecureHeader[0]) << 0) | ((uint16_t)signedSecureHeader[1]) << 8;
						uint8_t signatureSize = signedSecureHeader[2];
						const unsigned char *pEcKey = &signedSecureHeader[3];
						EC_KEY *pubKey = asymKey->getOpensslECKey();
						int secretLen;
						const unsigned char *pReadedSignature;
						const EC_POINT *ecPubkeyPoint = EC_KEY_get0_public_key(pubKey);
						unsigned char secureHeaderHash[20] = {0};
						int signedSecureHeaderPos = 3 + ecKeySize + signatureSize;
						AES_KEY headerKey;
						unsigned char iv[16];
						memcpy(iv, DATA_IV, sizeof(DATA_IV));

						BIO *privateKeyBio = BIO_new_mem_buf(pEcKey, ecKeySize);
						if (privateKeyBio) {
							PKCS8_PRIV_KEY_INFO *p8ki = d2i_PKCS8_PRIV_KEY_INFO_bio(privateKeyBio, NULL);
							if (p8ki)
							{
								EVP_PKEY *pkey = EVP_PKCS82PKEY(p8ki);
								if (pkey)
								{
									ecPrivateKey = EVP_PKEY_get1_EC_KEY(pkey);

									secretLen = EC_GROUP_get_degree(EC_KEY_get0_group(ecPrivateKey));
									secretLen = (secretLen + 7) / 8;
									tempSecretKey = (unsigned char*)malloc(secretLen);
									secretLen = ECDH_compute_key(tempSecretKey, secretLen, ecPubkeyPoint, ecPrivateKey, NULL);

									EVP_PKEY_free(pkey);
								} else {
									break;
								}
								PKCS8_PRIV_KEY_INFO_free(p8ki);
							} else {
								break;
							}
							BIO_free(privateKeyBio);
						} else {
							break;
						}

						SHA256(tempSecretKey, secretLen, sharedKey);
						AES_set_decrypt_key(sharedKey, 256, &headerKey);

						decodedSecureHeader = (unsigned char*)getMemoryAllocator()->allocate(rawHeader.signedSecureHeaderSize - signedSecureHeaderPos);
						memset(decodedSecureHeader, 0, rawHeader.signedSecureHeaderSize - signedSecureHeaderPos);
						AES_cbc_encrypt(&signedSecureHeader[signedSecureHeaderPos], decodedSecureHeader, rawHeader.signedSecureHeaderSize - signedSecureHeaderPos, &headerKey, iv, AES_DECRYPT);
						memcpy(&secureHeader, decodedSecureHeader, sizeof(secureHeader));

						pReadedSignature = &signedSecureHeader[3 + ecKeySize];
						ecsig = d2i_ECDSA_SIG(NULL, &pReadedSignature, signatureSize);
						SHA1((const unsigned char*)&secureHeader, sizeof(secureHeader), secureHeaderHash);
						orc = ECDSA_do_verify(secureHeaderHash, sizeof(secureHeaderHash), ecsig, pubKey);
						if (orc != 1)
						{
							causedException = exception::IntegrityException();
							break;
						}
					} else if (this->headerCipherAlgorithm == HeaderCipherAlgorithm::RSA) {
						decodedSecureHeader = (unsigned char*)getMemoryAllocator()->allocate(rawHeader.signedSecureHeaderSize);
						memset(decodedSecureHeader, 0xff, rawHeader.signedSecureHeaderSize);
						orc = RSA_public_decrypt(rawHeader.signedSecureHeaderSize, signedSecureHeader, decodedSecureHeader, this->asymKey->getOpensslRSAKey(), RSA_PKCS1_PADDING);
						if (orc < 0) {
							causedException = exception::IntegrityException();
							break;
						}

						memcpy(&secureHeader, decodedSecureHeader, sizeof(secureHeader));
					} else {
						break;
					}
#else
					break;
#endif

					if (memcmp(secureHeader.sig, SIGNATURE, sizeof(SIGNATURE)) || secureHeader.sig[15] != rawHeader.version)
					{
						causedException = exception::InvalidFileException();
						break;
					}

					result = true;
				} while (0);
				if (tempSecretKey)
					getMemoryAllocator()->release(tempSecretKey);
				if (decodedSecureHeader)
					getMemoryAllocator()->release(decodedSecureHeader);
				if (ecsig)
					ECDSA_SIG_free(ecsig);
				if (ecPrivateKey)
					EC_KEY_free(ecPrivateKey);
				if (ecPrivateGroup)
					EC_GROUP_free(ecPrivateGroup);
				getMemoryAllocator()->release(signedSecureHeader);
				if (!result)
				{
					if (exception)
						*exception = causedException;
					if (getUseCppThrow())
						throw causedException;
					return -1;
				}
				return 0;
			}
		}
		return 1;
	}

	bool Header::writeTo(Buffer &buffer, size_t computedHeaderSize, exception::SignedSecureFileException *exception)
	{
		// encrypt secureHeader
		int rc = 0;

		Buffer signedSecureHeaderBuffer;
		exception::SignedSecureFileException causedException;

#if defined(HAS_OPENSSL) && HAS_OPENSSL
		if (this->headerCipherAlgorithm == HeaderCipherAlgorithm::RSA)
		{
			rc = RSA_private_encrypt(sizeof(secureHeader), (const unsigned char*)&secureHeader, buffer.rawBuffer() + Header::COMMON_HEADER_SIZE, this->asymKey->getOpensslRSAKey(), RSA_PKCS1_PADDING);
			if (rc < 0) {
				causedException = exception::SignedSecureFileException("Fault", "RSA_private_encrypt failed");
				goto done;
			}
			rawHeader.signedSecureHeaderSize = rc;
		}
		else if (this->headerCipherAlgorithm == HeaderCipherAlgorithm::EC)
		{
			unsigned char *tempSecretKeyMem = NULL;
			unsigned char tempSecretKeyBuf[64];
			EC_KEY *signEcKey = asymKey->getOpensslECKey();
			EC_KEY *priKey = ecLocalPrivateKey;
			unsigned char *pTempSecretKey = tempSecretKeyBuf;
			unsigned char sigStackBuf[128];
			unsigned char *sigMemBuf = NULL;
			unsigned char *sigBufPtr = sigStackBuf;
			EVP_CIPHER_CTX *headerCipherCtx = EVP_CIPHER_CTX_new();

			signedSecureHeaderBuffer.allocate(this->outputSignedSecureHeaderTotalSize);

			do {
				unsigned char sharedKey[32];
				unsigned char iv[16];
				int secretLen = (EC_GROUP_get_degree(EC_KEY_get0_group(priKey)) + 7) / 8;
				unsigned char secureHeaderHash[20] = { 0 };
				int ecSigSize = ECDSA_size(signEcKey);
				unsigned int ecSigLen = 0;
				unsigned char encBuffer[32];
				int encLen;
				const unsigned char *encDataPtr;
				unsigned int encDataRemaining = sizeof(secureHeader);

				memcpy(iv, DATA_IV, sizeof(DATA_IV));
				SHA1((const unsigned char*)&secureHeader, sizeof(secureHeader), secureHeaderHash);
				if (secretLen > sizeof(tempSecretKeyBuf))
				{
					pTempSecretKey = tempSecretKeyMem = (unsigned char *)getMemoryAllocator()->allocate(secretLen);
				}
				secretLen = ECDH_compute_key(pTempSecretKey, secretLen, EC_KEY_get0_public_key(priKey), signEcKey, NULL);
				SHA256(pTempSecretKey, secretLen, sharedKey);
				EVP_CipherInit_ex(headerCipherCtx, EVP_aes_256_cbc(), NULL, sharedKey, iv, 1);
				if (sizeof(sigStackBuf) < ecSigSize) {
					sigBufPtr = sigMemBuf = (unsigned char*)getMemoryAllocator()->allocate(ecSigSize);
				}
				ecSigLen = ecSigSize;
				ECDSA_sign(0, secureHeaderHash, sizeof(secureHeaderHash), &ecSignedSecureHeader->privKey[ecSignedSecureHeader->privKeySize], (unsigned int*)&ecSigLen, signEcKey);
				ecSignedSecureHeader->sigSize = ecSigLen;
				signedSecureHeaderBuffer.write((const unsigned char*)ecSignedSecureHeader, 3 + ecSignedSecureHeader->privKeySize + ecSigLen);
				
				encDataPtr = (const unsigned char*)&secureHeader;
				do {
					unsigned int writtenSize = encDataRemaining > sizeof(encBuffer) ? sizeof(encBuffer) : encDataRemaining;
					int rc;
					encLen = 0;
					rc = EVP_CipherUpdate(headerCipherCtx, encBuffer, &encLen, encDataPtr, writtenSize);
					if (rc <= 0) {
						break;
					}
					encDataPtr += writtenSize;
					encDataRemaining -= writtenSize;
					if (encLen > 0) {
						signedSecureHeaderBuffer.write(encBuffer, encLen);
					}
				} while (encDataRemaining > 0);
				do {
					int rc;
					encLen = sizeof(encBuffer);
					rc = EVP_CipherFinal_ex(headerCipherCtx, encBuffer, &encLen);
					if (rc <= 0) {
						break;
					}
					if (encLen > 0) {
						signedSecureHeaderBuffer.write(encBuffer, encLen);
					}
				} while (0);

				buffer.setArrayOffset(computedHeaderSize - COMMON_HEADER_SIZE - signedSecureHeaderBuffer.readRemaining());
				rawHeader.signedSecureHeaderSize = signedSecureHeaderBuffer.readRemaining();
			} while (0);

			if (headerCipherCtx)
			{
				EVP_CIPHER_CTX_free(headerCipherCtx);
			}

			if (tempSecretKeyMem)
			{
				getMemoryAllocator()->release(tempSecretKeyMem);
			}
			if (sigMemBuf)
			{
				getMemoryAllocator()->release(sigMemBuf);
			}
		}
#endif

		buffer.insert(0, (const unsigned char*)&rawHeader, COMMON_HEADER_SIZE);
		if (signedSecureHeaderBuffer.readRemaining() > 0) {
			buffer.insert(Header::COMMON_HEADER_SIZE, (const unsigned char*)signedSecureHeaderBuffer.buffer(), signedSecureHeaderBuffer.readRemaining());
		}

		if (!_sysIsLitleEndian)
		{
			RawHeader_t *bufHeader = (RawHeader_t *)buffer.rawBuffer();
			int16toArray((unsigned char*)&bufHeader->signedSecureHeaderSize, bufHeader->signedSecureHeaderSize);
			int32toArray((unsigned char*)&bufHeader->keySize, bufHeader->keySize);
		}

done:
		if (rc < 0) {
			if (exception)
				*exception = causedException;
			if (getUseCppThrow()) {
				throw causedException;
			}
			return false;
		}

		return true;
	}

	void Header::int32toArray(unsigned char *buffer, uint32_t value)
	{
		if (_sysIsLitleEndian)
			*((uint32_t*)buffer) = value;
		else {
			buffer[0] = (unsigned char)((value) & 0xFF);
			buffer[1] = (unsigned char)((value >> 8) & 0xFF);
			buffer[2] = (unsigned char)((value >> 16) & 0xFF);
			buffer[3] = (unsigned char)((value >> 24) & 0xFF);
		}
	}

	void Header::arrayToInt32(const unsigned char *buffer, uint32_t *value)
	{
		if (_sysIsLitleEndian)
			*value = *((uint32_t*)buffer);
		else {
			*value = (((uint32_t)buffer[0]) << 0) | ((uint32_t)buffer[1]) << 8 | ((uint32_t)buffer[2]) << 16 | ((uint32_t)buffer[3]) << 24;
		}
	}

	void Header::int16toArray(unsigned char *buffer, uint16_t value)
	{
		if (_sysIsLitleEndian)
			*((uint16_t*)buffer) = value;
		else {
			buffer[0] = (unsigned char)((value) & 0xFF);
			buffer[1] = (unsigned char)((value >> 8) & 0xFF);
		}
	}

	void Header::arrayToInt16(const unsigned char *buffer, uint16_t *value)
	{
		if (_sysIsLitleEndian)
			*value = *((uint16_t*)buffer);
		else {
			*value = (((uint16_t)buffer[0]) << 0) | ((uint16_t)buffer[1]) << 8;
		}
	}
}
