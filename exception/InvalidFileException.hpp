/**
 * @file	InvalidFileException.h
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	InvalidFileException
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include "SignedSecureFileException.hpp"

namespace signedsecurefile {
	namespace exception {

		class InvalidFileException : public SignedSecureFileException
		{
		public:
			InvalidFileException() : SignedSecureFileException("InvalidFileException")
			{
			}
			virtual ~InvalidFileException()
			{
			}

			InvalidFileException(const char *message) : SignedSecureFileException("InvalidFileException", message)
			{
			}

			InvalidFileException(const char *message, int code) : SignedSecureFileException("InvalidFileException", message, code)
			{
			}
		};

	}
}
