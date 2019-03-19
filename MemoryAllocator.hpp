/**
 * @file	MemoryAllocator.h
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	MemoryAllocator
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#if (defined(_WIN32) && defined(_MSC_VER)) || (defined(_linux))
#include <stdlib.h>
#undef SIGNEDSECUREFILE_HAS_STDLIB
#define SIGNEDSECUREFILE_HAS_STDLIB 1
#endif

namespace signedsecurefile {
	class MemoryAllocator {
	public:
		virtual void *allocate(size_t size) = 0;
		virtual void release(void *ptr) = 0;
		virtual void *reallocate(void *ptr, size_t newsize) = 0;
	};

#if defined(SIGNEDSECUREFILE_HAS_STDLIB) && SIGNEDSECUREFILE_HAS_STDLIB == 1
	class StandardMemoryAllocator : public MemoryAllocator {
	public:
		void *allocate(size_t size) override
		{
			return malloc(size);
		}
		void release(void *ptr) override
		{
			return free(ptr);
		}
		void *reallocate(void *ptr, size_t newsize) override
		{
			return realloc(ptr, newsize);
		}
	};
#endif
}
