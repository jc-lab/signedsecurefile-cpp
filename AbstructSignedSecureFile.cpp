/**
 * @file	AbstructSignedSecureFile.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	AbstructSignedSecureFile
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "AbstructSignedSecureFile.hpp"

namespace signedsecurefile {


	AbstructSignedSecureFile::AbstructSignedSecureFile()
	{
		this->parent = NULL;
		this->useCppThrow = false;
		this->memoryAllocator = &standardMemoryAllocator;
	}

	AbstructSignedSecureFile::AbstructSignedSecureFile(const AbstructSignedSecureFile *parent)
	{
		this->parent = parent;
	}

	void AbstructSignedSecureFile::setParent(const AbstructSignedSecureFile *parent)
	{
		this->parent = parent;
	}

	AbstructSignedSecureFile::~AbstructSignedSecureFile()
	{
	}

	void AbstructSignedSecureFile::setUseCppThrow(bool useCppThrow)
	{
		this->useCppThrow = useCppThrow;
	}

	bool AbstructSignedSecureFile::getUseCppThrow() const
	{
		if (this->parent)
			return this->parent->getUseCppThrow();
		else
			return this->useCppThrow;
	}

	void AbstructSignedSecureFile::setMemoryAllocator(MemoryAllocator *memoryAllocator)
	{
		if(memoryAllocator)
			this->memoryAllocator = memoryAllocator;
		else
			this->memoryAllocator = &standardMemoryAllocator;
	}

	MemoryAllocator *AbstructSignedSecureFile::getMemoryAllocator() const
	{
		if (this->parent)
			return this->parent->getMemoryAllocator();
		else
			return this->memoryAllocator;
	}
}
