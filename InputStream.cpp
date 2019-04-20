/**
 * @file	InputStream.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	InputStream
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "InputStream.hpp"

#include "exception/IntegrityException.hpp"
#include "exception/InvalidFileException.hpp"

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include <openssl/err.h>
#endif

namespace signedsecurefile {

	InputStream::InputStream(Key *pubKey, const std::string& secretKey) : header(this)
	{
		this->useCppThrow = false;
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		dataHmacCtx = HMAC_CTX_new();
		dataKeyHmacCtx = HMAC_CTX_new();
		HMAC_Init_ex(dataHmacCtx, secretKey.c_str(), secretKey.length(), EVP_sha256(), NULL);
		HMAC_Init_ex(dataKeyHmacCtx, secretKey.c_str(), secretKey.length(), EVP_sha256(), NULL);
		dataEvpCtx = NULL;
#endif
		this->headerReaded = false;
		this->header.setAsymKey(pubKey);
	}

	InputStream::~InputStream()
	{
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		if(dataHmacCtx)
			HMAC_CTX_free(dataHmacCtx);
		if(dataKeyHmacCtx)
			HMAC_CTX_free(dataKeyHmacCtx);
		if (dataEvpCtx)
			EVP_CIPHER_CTX_free(dataEvpCtx);
#endif
	}

	int InputStream::input(const unsigned char *payload, size_t size, exception::SignedSecureFileException *exception)
	{
		int rc;
		unsigned char decryptDataBuffer[128 + 32];
		if (!headerReaded)
		{
			buffer.write(payload, size);
			rc = header.readBuffer(buffer);
			if (rc == 0)
			{
				size_t datasize = buffer.readRemaining();
				unsigned char dateKey[32];
				unsigned int dataKeyLen = sizeof(dateKey);
				headerReaded = true;
#if defined(HAS_OPENSSL) && HAS_OPENSSL
				int orc;
				DataCipherAlgorithm dataCipherAlgo = header.getDataCipherAlgorithm();
				dataEvpCtx = EVP_CIPHER_CTX_new();

				HMAC_Update(dataKeyHmacCtx, header.secureHeader.key, sizeof(header.secureHeader.key));
				HMAC_Final(dataKeyHmacCtx, dateKey, &dataKeyLen);
				HMAC_CTX_reset(dataKeyHmacCtx);

				if (dataCipherAlgo == DataCipherAlgorithm::AES) {
					EVP_CipherInit_ex(dataEvpCtx, EVP_aes_256_cbc(), NULL, NULL, NULL, 0);
					if ((EVP_CIPHER_CTX_key_length(dataEvpCtx) != 32) || (EVP_CIPHER_CTX_iv_length(dataEvpCtx) != 16))
					{
						return -1;
					}
				}

				EVP_CipherInit_ex(dataEvpCtx, NULL, NULL, dateKey, Header::DATA_IV, 0);
				if (datasize) {
					size_t remaining = datasize;
					int outlen;
					do {
						unsigned int writtenSize = remaining > 128 ? 128 : remaining;
						const unsigned char *ptr = buffer.readBuffer(writtenSize);
						outlen = 0;
						orc = EVP_CipherUpdate(dataEvpCtx, decryptDataBuffer, &outlen, ptr, writtenSize);
						if (orc <= 0) {
							break;
						}
						if (outlen > 0) {
							decryptedDataBuffer.write(decryptDataBuffer, outlen);
							HMAC_Update(dataHmacCtx, decryptDataBuffer, outlen);
						}
						remaining -= writtenSize;
						datasize = 0;
					} while (remaining > 0);
				}
#endif
			} else if(rc < 0) {
				return rc;
			}
		} else {
			int outlen;
			size_t remaining = size;
			do {
				unsigned int writtenSize = remaining > 128 ? 128 : remaining;
				const unsigned char *ptr = payload;
				int rc;
				outlen = 0;
				rc = EVP_CipherUpdate(dataEvpCtx, decryptDataBuffer, &outlen, ptr, writtenSize);
				if (rc <= 0) {
					break;
				}
				if (outlen > 0) {
					decryptedDataBuffer.write(decryptDataBuffer, outlen);
					HMAC_Update(dataHmacCtx, decryptDataBuffer, outlen);
				}
				payload += writtenSize;
				remaining = writtenSize;
			} while (remaining > 0);
		}
		return rc;
	}

	int InputStream::done(exception::SignedSecureFileException *exception)
	{
		exception::SignedSecureFileException causedException;
		int outlen;
		unsigned char computedHmac[32] = {0};
		unsigned int hmacLen = 32;
		int orc;

		if (!headerReaded)
			return -1;

		{
			unsigned char decryptDataBuffer[1024];
			outlen = sizeof(decryptDataBuffer);
			ERR_clear_error();
			orc = EVP_CipherFinal_ex(dataEvpCtx, decryptDataBuffer, &outlen);
			if (orc != 1)
			{
				unsigned int oerr = ERR_get_error();
				char buffer[1024];
				ERR_error_string(oerr, buffer);
				causedException = exception::IntegrityException();
				if (exception)
					*exception = causedException;
				if (this->useCppThrow)
					throw causedException;
				return 0;
			}
			if (outlen > 0) {
				decryptedDataBuffer.write(decryptDataBuffer, outlen);
				HMAC_Update(dataHmacCtx, decryptDataBuffer, outlen);
			}
		}
		HMAC_Final(dataHmacCtx, computedHmac, &hmacLen);

		if (decryptedDataBuffer.position() < header.secureHeader.datasize)
		{
			causedException = exception::InvalidFileException("need more data");
			if (exception)
				*exception = causedException;
			if (this->useCppThrow)
				throw causedException;
			return 0;
		}

		if (memcmp(header.secureHeader.hmac, computedHmac, sizeof(header.secureHeader.hmac)))
		{
			causedException = exception::IntegrityException();
			if (exception)
				*exception = causedException;
			if (this->useCppThrow)
				throw causedException;
			return 0;
		}

		return 1;
	}

	int InputStream::read(unsigned char *buffer, size_t size) {
		return decryptedDataBuffer.read(buffer, size);
	}
}
