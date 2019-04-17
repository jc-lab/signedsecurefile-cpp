/**
 * @file	OutputStream.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	OutputStream
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "OutputStream.hpp"

namespace signedsecurefile {

	OutputStream::OutputStream(Key *priKey, const std::string& secretKey, exception::SignedSecureFileException *exception) : 
		header(this)
	{
		unsigned char dataKey[32] = {0};
		unsigned int dataKeyLen = sizeof(dataKey);

		this->header.setAsymKey(priKey, true);
		this->header.generateKey();
		this->header.setDataCipherAlgorithm(DataCipherAlgorithm::AES);
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		HMAC_CTX *dataKeyHmacCtx = HMAC_CTX_new();
		dataHmacCtx = HMAC_CTX_new();
		HMAC_Init_ex(dataKeyHmacCtx, secretKey.c_str(), secretKey.length(), EVP_sha256(), NULL);
		HMAC_Init_ex(dataHmacCtx, secretKey.c_str(), secretKey.length(), EVP_sha256(), NULL);
		HMAC_Update(dataKeyHmacCtx, this->header.secureHeader.key, sizeof(this->header.secureHeader.key));
		HMAC_Final(dataKeyHmacCtx, dataKey, &dataKeyLen);
		HMAC_CTX_free(dataKeyHmacCtx);
		dataEvpCtx = EVP_CIPHER_CTX_new();
		EVP_CipherInit_ex(dataEvpCtx, EVP_aes_256_cbc(), NULL, dataKey, Header::DATA_IV, 1);
#endif
		this->computedHeaderSize = Header::COMMON_HEADER_SIZE + header.getSignedSecureHeaderSize();
		this->buffer.writeZero(this->computedHeaderSize);
	}

	OutputStream::~OutputStream()
	{
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		if(dataHmacCtx)
			HMAC_CTX_free(dataHmacCtx);
		if (dataEvpCtx)
			EVP_CIPHER_CTX_free(dataEvpCtx);
#endif
	}

	int OutputStream::write(const unsigned char *buffer, size_t size)
	{
		const unsigned char *writePtr = buffer;
		size_t remaining = size;
		int outLen;
		HMAC_Update(dataHmacCtx, buffer, size);
		this->header.secureHeader.datasize += size;
		do {
			int rc;
			unsigned char out[256];
			unsigned int writtenSize = remaining > sizeof(out) ? sizeof(out) : remaining;
			outLen = 0;
			rc = EVP_CipherUpdate(dataEvpCtx, out, &outLen, writePtr, writtenSize);
			if (rc <= 0)
			{
				// Error
				break;
			}
			remaining -= writtenSize;
			writePtr += writtenSize;

			if(outLen > 0)
				this->buffer.write(out, outLen);
		} while (remaining > 0);
		return size;
	}

	int OutputStream::save(exception::SignedSecureFileException *exception)
	{
		unsigned char hmac[32];
		unsigned int hmacLen = sizeof(hmac);
		int outLen;
		int rc;
		unsigned char out[256];
		outLen = sizeof(out);
		rc = EVP_CipherFinal(dataEvpCtx, out, &outLen);
		if (rc > 0)
		{
			if (outLen > 0)
				this->buffer.write(out, outLen);
		}
		HMAC_Final(dataHmacCtx, hmac, &hmacLen);
		memcpy(header.secureHeader.hmac, hmac, hmacLen);
		if (header.writeTo(this->buffer, this->computedHeaderSize, exception))
		{
			return 0;
		}
		return -1;
	}
}

