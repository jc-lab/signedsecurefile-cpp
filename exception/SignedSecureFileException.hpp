/**
 * @file	SignedSecureFileException.h
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	SignedSecureFileException
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <exception>
#include <string>

namespace signedsecurefile {
	namespace exception {

		class SignedSecureFileException : public std::exception
		{
		private:
			std::string type;

		protected:
			SignedSecureFileException(const char *type)
			{
				this->type = type;
			}

		public:
			SignedSecureFileException() {}
			virtual ~SignedSecureFileException() {}

			SignedSecureFileException(const char *type, const char *message) : std::exception(message)
			{
				this->type = type;
			}

			SignedSecureFileException(const char *type, const char *message, int code) : std::exception(message, code)
			{
				this->type = type;
			}

			SignedSecureFileException(const SignedSecureFileException &other) : std::exception(other.what())
			{
				this->type = other.getType();
			}

			std::string getType() const { return this->type; }
		};

	}
}
