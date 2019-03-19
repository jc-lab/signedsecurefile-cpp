/**
 * @file	AbstructSignedSecureFile.h
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	AbstructSignedSecureFile
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include <string>
#include "MemoryAllocator.hpp"

namespace signedsecurefile {

	class AbstructSignedSecureFile
	{
	private:
		bool useCppThrow;
		MemoryAllocator *memoryAllocator;
#if defined(SIGNEDSECUREFILE_HAS_STDLIB) && SIGNEDSECUREFILE_HAS_STDLIB == 1
		StandardMemoryAllocator standardMemoryAllocator;
#endif
		const AbstructSignedSecureFile *parent;

	public:
		AbstructSignedSecureFile();
		AbstructSignedSecureFile(const AbstructSignedSecureFile *parent);
		virtual ~AbstructSignedSecureFile();
		
		void setUseCppThrow(bool useCppThrow);
		bool getUseCppThrow() const;
		void setMemoryAllocator(MemoryAllocator *memoryAllocator);
		MemoryAllocator *getMemoryAllocator() const;

	protected:
		void setParent(const AbstructSignedSecureFile *parent);
	};

}
