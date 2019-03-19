/**
 * @file	signedsecurefile.h
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	signedsecurefile
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include "SignedSecureFileException.hpp"

namespace signedsecurefile {
	namespace exception {

		class InvalidKeyException : public SignedSecureFileException
		{
		public:
			InvalidKeyException() : SignedSecureFileException("InvalidKeyException")
			{
			}
			virtual ~InvalidKeyException()
			{
			}

			InvalidKeyException(const char *message) : SignedSecureFileException("InvalidKeyException", message)
			{
			}

			InvalidKeyException(const char *message, int code) : SignedSecureFileException("InvalidKeyException", message, code)
			{
			}
		};

	}
}
