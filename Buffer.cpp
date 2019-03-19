/**
 * @file	Buffer.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/146 )
 * @class	Buffer
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "Buffer.hpp"

#include <string.h>

namespace signedsecurefile {

	Buffer::Buffer(MemoryAllocator *memoryAllocator)
	{
		if (memoryAllocator)
		{
			this->memoryAllocator = memoryAllocator;
		} else {
#if defined(SIGNEDSECUREFILE_HAS_STDLIB) && SIGNEDSECUREFILE_HAS_STDLIB == 1
			this->memoryAllocator = &standardMemoryAllocator;
#else
			this->memoryAllocator = NULL;
#endif
		}

		m_buffer = NULL;
		m_offset = 0;
		m_size = 0;
		m_limit = 0;
		m_pos = 0;
		m_readpos = 0;
	}

	Buffer::~Buffer()
	{
		if (m_buffer)
		{
			this->memoryAllocator->release(m_buffer);
			m_buffer = NULL;
			m_offset = 0;
			m_size = 0;
			m_limit = 0;
			m_pos = 0;
			m_readpos = 0;
		}
	}

	void Buffer::allocate(size_t size)
	{
		if (size > m_size)
		{
			size_t chunksize = size / 1024;
			size_t newsize = m_size;
			unsigned char *newbuf;
			if (size % 1024) {
				chunksize++;
			}
			newsize += chunksize * 1024;
			newbuf = (unsigned char*)this->memoryAllocator->reallocate(this->m_buffer, newsize);
			m_buffer = newbuf;
			m_size = newsize;
		}
	}

	void Buffer::write(const unsigned char *src, size_t length)
	{
		size_t aftersize = m_pos + length;
		if (aftersize > m_size)
		{
			size_t chunksize = aftersize / 1024;
			size_t newsize = m_size;
			unsigned char *newbuf;
			if (aftersize % 1024) {
				chunksize++;
			}
			newsize += chunksize * 1024;
			newbuf = (unsigned char*)this->memoryAllocator->reallocate(this->m_buffer, newsize);
			m_buffer = newbuf;
			m_size = newsize;
		}
		memcpy(&m_buffer[m_pos], src, length);
		m_pos += length;
		m_limit += length;
	}

	void Buffer::writeZero(size_t length)
	{
		size_t aftersize = m_pos + length;
		if (aftersize > m_size)
		{
			size_t chunksize = aftersize / 1024;
			size_t newsize = m_size;
			unsigned char *newbuf;
			if (aftersize % 1024) {
				chunksize++;
			}
			newsize += chunksize * 1024;
			newbuf = (unsigned char*)this->memoryAllocator->reallocate(this->m_buffer, newsize);
			m_buffer = newbuf;
			m_size = newsize;
		}
		memset(&m_buffer[m_pos], 0, length);
		m_pos += length;
		m_limit += length;
	}

	void Buffer::insert(size_t pos, const unsigned char *src, size_t length)
	{
		size_t aftersize = m_offset + pos + length;
		if (aftersize > m_size)
		{
			size_t chunksize = aftersize / 1024;
			size_t newsize = m_size;
			unsigned char *newbuf;
			if (aftersize % 1024) {
				chunksize++;
			}
			newsize += chunksize * 1024;
			newbuf = (unsigned char*)this->memoryAllocator->reallocate(this->m_buffer, newsize);
			m_buffer = newbuf;
			m_size = newsize;
		}
		memcpy(&m_buffer[m_offset + pos], src, length);
		if (m_pos < aftersize)
			m_pos = aftersize;
		if (m_limit < aftersize)
			m_limit = aftersize;
	}

	size_t Buffer::read(unsigned char *dest, size_t size)
	{
		size_t remainingSize = readRemaining();
		size_t readsize = (size > remainingSize) ? remainingSize : size;
		memcpy(dest, &m_buffer[m_readpos], readsize);
		m_readpos += readsize;
		return readsize;
	}

	size_t Buffer::read(Buffer *dest, size_t size)
	{
		size_t remainingSize = readRemaining();
		size_t readsize = (size > remainingSize) ? remainingSize : size;
		dest->write(&m_buffer[m_readpos], readsize);
		m_readpos += readsize;
		return readsize;
	}

	void Buffer::flip()
	{
		m_limit = m_pos;
		m_pos = m_offset;
		m_readpos = m_offset;
	}

	void Buffer::clear()
	{
		m_offset = 0;
		m_limit = 0;
		m_pos = 0;
		m_readpos = 0;
	}

	void Buffer::setArrayOffset(size_t offset)
	{
		size_t aftersize = offset;
		if (aftersize > m_size)
		{
			size_t chunksize = aftersize / 1024;
			size_t newsize = m_size;
			unsigned char *newbuf;
			if (aftersize % 1024) {
				chunksize++;
			}
			newsize += chunksize * 1024;
			newbuf = (unsigned char*)this->memoryAllocator->reallocate(this->m_buffer, newsize);
			m_buffer = newbuf;
			m_size = newsize;
		}
		m_offset = offset;
	}
}
