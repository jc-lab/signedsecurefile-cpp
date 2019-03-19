/**
 * @file	IntegrityException.h
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	IntegrityException
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include "SignedSecureFileException.hpp"

namespace signedsecurefile {
	namespace exception {

		class IntegrityException : public SignedSecureFileException
		{
		public:
			IntegrityException() : SignedSecureFileException("IntegrityException")
			{
			}
			virtual ~IntegrityException()
			{
			}

			IntegrityException(const char *message) : SignedSecureFileException("IntegrityException", message)
			{
			}

			IntegrityException(const char *message, int code) : SignedSecureFileException("IntegrityException", message, code)
			{
			}
		};

	}
}
