/**
 * @file	OutputStream.h
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	OutputStream
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */#pragma once

#include <string>

#include "AbstructSignedSecureFile.hpp"
#include "Key.hpp"
#include "Header.hpp"
#include "Buffer.hpp"

#if defined(HAS_OPENSSL) && HAS_OPENSSL
#include <openssl/hmac.h>
#include <openssl/aes.h>
#endif

namespace signedsecurefile {

	class OutputStream : public AbstructSignedSecureFile
	{
	private:
#if defined(HAS_OPENSSL) && HAS_OPENSSL
		HMAC_CTX *dataHmacCtx;
		EVP_CIPHER_CTX *dataEvpCtx;
#endif

		size_t computedHeaderSize;
		Buffer buffer;
		Header header;

	public:
		OutputStream(Key *pubKey, const std::string& secretKey, exception::SignedSecureFileException *exception = NULL);
		~OutputStream();

		int write(const unsigned char *buffer, size_t size);
		int save(exception::SignedSecureFileException *exception = NULL);

		Buffer *toBuffer() { return &buffer; }
	};

}
