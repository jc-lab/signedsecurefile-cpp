/**
 * @file	Buffer.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	Buffer
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#include "MemoryAllocator.hpp"

namespace signedsecurefile {

	class Buffer
	{
	private:
#if defined(SIGNEDSECUREFILE_HAS_STDLIB) && SIGNEDSECUREFILE_HAS_STDLIB == 1
		StandardMemoryAllocator standardMemoryAllocator;
#endif
		MemoryAllocator *memoryAllocator;

		unsigned char *m_buffer;
		size_t m_offset;
		size_t m_size;
		size_t m_limit;
		size_t m_pos;
		size_t m_readpos;

	public:
		Buffer(MemoryAllocator *memoryAllocator = NULL);
		virtual ~Buffer();

		void allocate(size_t size);
		void write(const unsigned char *src, size_t length);
		void writeZero(size_t length);
		void insert(size_t pos, const unsigned char *src, size_t length);
		size_t read(unsigned char *dest, size_t size);
		size_t read(Buffer *dest, size_t size);
		void flip();
		void clear();

		void setArrayOffset(size_t offset);
		
		const unsigned char *buffer() const { return m_buffer + m_offset; }
		unsigned char *rawBuffer() { return m_buffer + m_offset; }
		const unsigned char *readBuffer(size_t size) { const unsigned char *ptr = m_buffer + m_readpos; m_readpos += size; return ptr; }
		size_t remaining() const { return m_limit - m_pos - m_offset; }
		size_t readRemaining() const { return m_limit - m_readpos - m_offset; }
		size_t position() const { return m_pos - m_offset; }
	};

}

