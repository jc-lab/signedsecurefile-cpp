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

#include <vector>

#if defined(HAS_OPENSSL) && HAS_OPENSSL
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
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
#include <assert.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/asn1.h>
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
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
		mbedtls_entropy_init(&entropy_ctx);
		mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
		mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
#endif
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
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
		mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
		mbedtls_entropy_free(&entropy_ctx);
#endif
	}

#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
	static int mbedtls_raw2bn(mbedtls_mpi *x, const unsigned char *data, size_t size)
	{
		if (data[0] >= 0x80)
		{
			std::string temp(1, 0x00);
			temp.append((const char*)data, size);
			return mbedtls_mpi_read_binary(x, (const unsigned char*)temp.data(), temp.size());
		}
		return mbedtls_mpi_read_binary(x, data, size);
	}

	static void mbedtls_SHA256(const unsigned char *d, size_t n, unsigned char *md)
	{
		mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), d, n, md);
	}

	static int mbedtls_read_ecdsa_signature(const unsigned char *begin, const unsigned char *end, mbedtls_mpi *r, mbedtls_mpi *s)
	{
		int ret;
		size_t len;
		unsigned char *p = (unsigned char*)begin;

		if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
			MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
			return(MBEDTLS_ERR_PK_INVALID_PUBKEY + ret);

		if (p + len != end)
			return(MBEDTLS_ERR_PK_INVALID_PUBKEY +
				MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);

		if ((ret = mbedtls_asn1_get_mpi(&p, end, r)) != 0 ||
			(ret = mbedtls_asn1_get_mpi(&p, end, s)) != 0)
			return(MBEDTLS_ERR_PK_INVALID_PUBKEY + ret);

		if (p != end)
			return(MBEDTLS_ERR_PK_INVALID_PUBKEY +
				MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);

		return(0);
	}

#endif

	void Header::setAsymKey(Key *key, bool encMode)
	{
		int librc;
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
#if defined(HAS_OPENSSL) && HAS_OPENSSL
				if (key->isOpensslKey()) {
					this->outputSignedSecureHeaderTotalSize = RSA_size(key->getOpensslRSAKey());
				}
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
				if (key->isMbedtlsKey()) {
					this->outputSignedSecureHeaderTotalSize = mbedtls_rsa_get_len(key->getMbedtlsRSAKey());
				}
#endif
			}
			else if (key->isECKey())
			{
				setHeaderCipherAlgorithm(HeaderCipherAlgorithm::EC);

				if (encMode)
				{
#if defined(HAS_OPENSSL) && HAS_OPENSSL
					if (key->isOpensslKey()) {
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
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
					if (key->isMbedtlsKey()) {
						assert("NOT SUPPORT YET" == false);
						const mbedtls_ecp_keypair *ecKey = this->asymKey->getMbedtlsECKey();
						int signatureSize = MBEDTLS_ECDSA_MAX_LEN;
						unsigned char prefixHeader[3];
						size_t encodedSecureHeaderSize = sizeof(secureHeader);
						mbedtls_pk_context newKeyPk;
						size_t plen;
						std::vector<unsigned char> tempBuffer;

						mbedtls_pk_init(&newKeyPk);
						mbedtls_pk_setup(&newKeyPk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
						mbedtls_ecp_gen_key(ecKey->grp.id, mbedtls_pk_ec(newKeyPk), mbedtls_ctr_drbg_random, &ctr_drbg_ctx);
						plen = mbedtls_pk_get_len(&newKeyPk);

						do {
							tempBuffer.resize(tempBuffer.size() + 1024);
							librc = mbedtls_pk_write_key_der(&newKeyPk, &tempBuffer[0], tempBuffer.capacity());
						} while (librc == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);

						ecSignedSecureHeader = (ECSignedSecureHeader_t*)getMemoryAllocator()->allocate(3 + librc + signatureSize);
						ecSignedSecureHeader->privKeySize = librc;
						ecSignedSecureHeader->sigSize = signatureSize;
						outputSignedSecureHeaderTotalSize = 3 + librc + ecSignedSecureHeader->sigSize;
						memcpy(ecSignedSecureHeader->privKey, &tempBuffer[0], librc);

						encodedSecureHeaderSize += 1;
						if (encodedSecureHeaderSize % 16)
						{
							encodedSecureHeaderSize += 16 - (encodedSecureHeaderSize % 16);
						}
						this->outputSignedSecureHeaderDataSize = encodedSecureHeaderSize;
						this->outputSignedSecureHeaderTotalSize += encodedSecureHeaderSize;
					}
#endif
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
		if (asymKey->isOpensslKey()) {
			if (headerCipherAlgorithm == HeaderCipherAlgorithm::RSA)
			{
				return RSA_size(this->asymKey->getOpensslRSAKey());
			}
			else if (headerCipherAlgorithm == HeaderCipherAlgorithm::EC)
			{
				return this->outputSignedSecureHeaderTotalSize;
			}
		}
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
		if (asymKey->isMbedtlsKey()) {
			if (headerCipherAlgorithm == HeaderCipherAlgorithm::RSA)
			{
				return mbedtls_rsa_get_len(this->asymKey->getMbedtlsRSAKey());
			}
			else if (headerCipherAlgorithm == HeaderCipherAlgorithm::EC)
			{
				return this->outputSignedSecureHeaderTotalSize;
			}
		}
#endif
		return -1;
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
#if defined(HAS_OPENSSL) && HAS_OPENSSL
				EC_KEY *ecPrivateKey = NULL;
				EC_GROUP *ecPrivateGroup = NULL;
				ECDSA_SIG *ecsig = NULL;
#endif
				int orc;
				buffer.read(signedSecureHeader, rawHeader.signedSecureHeaderSize);
				do {
					if (this->headerCipherAlgorithm == HeaderCipherAlgorithm::EC)
					{
						uint16_t ecKeySize = (((uint16_t)signedSecureHeader[0]) << 0) | ((uint16_t)signedSecureHeader[1]) << 8;
						uint8_t signatureSize = signedSecureHeader[2];
						const unsigned char *pEcKey = &signedSecureHeader[3];
						int secretLen;
						const unsigned char *pReadedSignature;
						unsigned char secureHeaderHash[32] = { 0 };
						int signedSecureHeaderPos = 3 + ecKeySize + signatureSize;
						unsigned char iv[16];

						memcpy(iv, DATA_IV, sizeof(DATA_IV));

#if defined(HAS_OPENSSL) && HAS_OPENSSL
						if (asymKey->isOpensslKey()) {
							AES_KEY headerKey;
							EC_KEY *pubKey = asymKey->getOpensslECKey();
							const EC_POINT *ecPubkeyPoint = EC_KEY_get0_public_key(pubKey);

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
									}
									else {
										break;
									}
									PKCS8_PRIV_KEY_INFO_free(p8ki);
								}
								else {
									break;
								}
								BIO_free(privateKeyBio);
							}
							else {
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
							SHA256((const unsigned char*)&secureHeader, sizeof(secureHeader), secureHeaderHash);
							orc = ECDSA_do_verify(secureHeaderHash, sizeof(secureHeaderHash), ecsig, pubKey);
							if (orc != 1)
							{
								causedException = exception::IntegrityException();
								break;
							}
						}
#endif

#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
						if (asymKey->isMbedtlsKey()) {
							const mbedtls_ecp_keypair *mkey = asymKey->getMbedtlsECKey();

							size_t molen = 0;

							{
								mbedtls_pk_context pk_ctx;
								mbedtls_pk_init(&pk_ctx);
								orc = mbedtls_pk_parse_key(&pk_ctx, pEcKey, ecKeySize, NULL, 0);
								if (orc == 0)
								{
									const mbedtls_ecp_keypair *mprikey = mbedtls_pk_ec(pk_ctx);
									mbedtls_mpi z;
									mbedtls_mpi_init(&z);
									orc = mbedtls_ecdh_compute_shared((mbedtls_ecp_group*)&mkey->grp, &z, &mkey->Q, &mprikey->d, mbedtls_ctr_drbg_random, &ctr_drbg_ctx);
									if (orc == 0)
									{
										secretLen = mbedtls_mpi_size(&z);
										tempSecretKey = (unsigned char*)malloc(secretLen);
										mbedtls_mpi_write_binary(&z, tempSecretKey, secretLen);
									}
									mbedtls_mpi_free(&z);
								}
								mbedtls_pk_free(&pk_ctx);
							}

							mbedtls_SHA256(tempSecretKey, secretLen, sharedKey);

							{
								mbedtls_aes_context headerCipher;
								mbedtls_aes_init(&headerCipher);
								mbedtls_aes_setkey_dec(&headerCipher, sharedKey, 256);

								decodedSecureHeader = (unsigned char*)getMemoryAllocator()->allocate(rawHeader.signedSecureHeaderSize - signedSecureHeaderPos);
								memset(decodedSecureHeader, 0, rawHeader.signedSecureHeaderSize - signedSecureHeaderPos);
								mbedtls_aes_crypt_cbc(&headerCipher, MBEDTLS_AES_DECRYPT, rawHeader.signedSecureHeaderSize - signedSecureHeaderPos, iv, &signedSecureHeader[signedSecureHeaderPos], decodedSecureHeader);
								memcpy(&secureHeader, decodedSecureHeader, sizeof(secureHeader));
								mbedtls_aes_free(&headerCipher);
							}

							pReadedSignature = &signedSecureHeader[3 + ecKeySize];

							{
								unsigned char *ppos = (unsigned char *)pReadedSignature;
								mbedtls_mpi r;
								mbedtls_mpi s;

								mbedtls_mpi_init(&r);
								mbedtls_mpi_init(&s);

								mbedtls_read_ecdsa_signature(pReadedSignature, pReadedSignature + signatureSize, &r, &s);

								mbedtls_SHA256((const unsigned char*)&secureHeader, sizeof(secureHeader), secureHeaderHash);
								//orc = mbedtls_ecdsa_verify((mbedtls_ecp_group*)&mkey->grp, secureHeaderHash, sizeof(secureHeaderHash), &mkey->Q, &r, &s);
								mbedtls_ecdsa_context ecdsa;
								mbedtls_ecdsa_init(&ecdsa);
								mbedtls_ecdsa_from_keypair(&ecdsa, mkey);
								orc = mbedtls_ecdsa_read_signature(&ecdsa, secureHeaderHash, sizeof(secureHeaderHash), pReadedSignature, signatureSize);

								mbedtls_mpi_free(&r);
								mbedtls_mpi_free(&s);
							}

							if (orc != 0)
							{
								causedException = exception::IntegrityException();
								break;
							}
						}
#endif
					}
					else if (this->headerCipherAlgorithm == HeaderCipherAlgorithm::RSA) {
						decodedSecureHeader = (unsigned char*)getMemoryAllocator()->allocate(rawHeader.signedSecureHeaderSize);
						memset(decodedSecureHeader, 0xff, rawHeader.signedSecureHeaderSize);

#if defined(HAS_OPENSSL) && HAS_OPENSSL
						if (asymKey->isOpensslKey()) {
							orc = RSA_public_decrypt(rawHeader.signedSecureHeaderSize, signedSecureHeader, decodedSecureHeader, this->asymKey->getOpensslRSAKey(), RSA_PKCS1_PADDING);
							if (orc < 0) {
								causedException = exception::IntegrityException();
								break;
							}
						}
#endif
#if defined(HAS_MBEDTLS) && HAS_MBEDTLS
						if (asymKey->isMbedtlsKey()) {
							size_t molen = 0;
							orc = mbedtls_rsa_pkcs1_decrypt((mbedtls_rsa_context*)asymKey->getMbedtlsRSAKey(), mbedtls_ctr_drbg_random, &ctr_drbg_ctx, MBEDTLS_RSA_PUBLIC, &molen, signedSecureHeader, decodedSecureHeader, rawHeader.signedSecureHeaderSize);
							if (orc != 0) {
								causedException = exception::IntegrityException();
								break;
							}
						}
#endif

						memcpy(&secureHeader, decodedSecureHeader, sizeof(secureHeader));
					}
					else {
						break;
					}

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
#if defined(HAS_OPENSSL) && HAS_OPENSSL
				if (ecsig)
					ECDSA_SIG_free(ecsig);
				if (ecPrivateKey)
					EC_KEY_free(ecPrivateKey);
				if (ecPrivateGroup)
					EC_GROUP_free(ecPrivateGroup);
#endif
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
				unsigned char secureHeaderHash[32] = { 0 };
				int ecSigSize = ECDSA_size(signEcKey);
				unsigned int ecSigLen = 0;
				unsigned char encBuffer[32];
				int encLen;
				const unsigned char *encDataPtr;
				unsigned int encDataRemaining = sizeof(secureHeader);

				memcpy(iv, DATA_IV, sizeof(DATA_IV));
				SHA256((const unsigned char*)&secureHeader, sizeof(secureHeader), secureHeaderHash);
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
