/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
   /*!
	   @file DefaultAlgorithms.cpp
	   Implementation of the default algorithms that works with a CryptedObject.
   */
#include "xtea.hpp"

#include <LibLyketo/DefaultAlgorithms.hpp>

#include <lzokay/lzokay.hpp>
#include <snappy.h>

#define MAKEFOURCC(ch0, ch1, ch2, ch3) ((uint32_t)(uint8_t)(ch0) | ((uint32_t)(uint8_t)(ch1) << 8) | ((uint32_t)(uint8_t)(ch2) << 16) | ((uint32_t)(uint8_t)(ch3) << 24))

// LZO (MCOZ)
DefaultAlgorithmLzo1x::DefaultAlgorithmLzo1x()
{
	m_dwFourCC = MAKEFOURCC('M', 'C', 'O', 'Z');
}

bool DefaultAlgorithmLzo1x::Compress(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength)
{
	if (!pbOutput || !pbInput || dwInputLength < 1 || !pdwOutputLength || *pdwOutputLength < 1)
		return false;

	size_t zOutSize;
	auto r = lzokay::compress(pbInput, dwInputLength, pbOutput, *pdwOutputLength, zOutSize);
	*pdwOutputLength = static_cast<uint32_t>(zOutSize);
	return r == lzokay::EResult::Success;
}

bool DefaultAlgorithmLzo1x::Decompress(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength)
{
	if (!pbOutput || !pbInput || dwInputLength < 1 || !pdwOutputLength || *pdwOutputLength < 1)
		return false;

	size_t zOutSize;
	auto r = lzokay::decompress(pbInput, dwInputLength, pbOutput, *pdwOutputLength, zOutSize);

	*pdwOutputLength = static_cast<uint32_t>(zOutSize);
	return r == lzokay::EResult::Success;
}

size_t DefaultAlgorithmLzo1x::GetWrostSize(size_t dwOriginalSize)
{
	return lzokay::compress_worst_size(dwOriginalSize);
}

bool DefaultAlgorithmLzo1x::HaveCryptation()
{
	return true;
}

uint32_t DefaultAlgorithmLzo1x::Decrypt(const uint8_t* input, uint8_t* output, size_t size, const uint32_t* key)
{
	return XTEA::Decrypt(input, output, size, key, 32);
}

void DefaultAlgorithmLzo1x::Encrypt(const uint8_t* input, uint8_t* output, size_t size, const uint32_t* key)
{
	return XTEA::Encrypt(input, output, size, key, 32);
}

// ------------------------------------------------------------------------------------------------------------------

// Snappy (MCPS)
DefaultAlgorithmSnappy::DefaultAlgorithmSnappy()
{
	m_dwFourCC = MAKEFOURCC('M', 'C', 'S', 'P');
}

bool DefaultAlgorithmSnappy::Compress(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength)
{
	if (!pbOutput || !pbInput || dwInputLength < 1 || !pdwOutputLength || *pdwOutputLength < 1)
		return false;

	std::string szUncompress;
	
	if (!snappy::Compress(reinterpret_cast<const char*>(pbInput), dwInputLength, &szUncompress))
		return false;

	memcpy_s(pbOutput, *pdwOutputLength, szUncompress.data(), szUncompress.size());
	*pdwOutputLength = static_cast<uint32_t>(szUncompress.size());
	return true;
}

bool DefaultAlgorithmSnappy::Decompress(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength)
{
	if (!pbOutput || !pbInput || dwInputLength < 1 || !pdwOutputLength || *pdwOutputLength < 1)
		return false;

	std::string szUncompress;
	
	if (!snappy::Uncompress(reinterpret_cast<const char*>(pbInput), dwInputLength, &szUncompress))
		return false;

	memcpy_s(pbOutput, *pdwOutputLength, szUncompress.data(), szUncompress.size());
	*pdwOutputLength = static_cast<uint32_t>(szUncompress.size());
	return true;
}

size_t DefaultAlgorithmSnappy::GetWrostSize(size_t dwOriginalSize)
{
	return snappy::MaxCompressedLength(dwOriginalSize);
}

uint32_t DefaultAlgorithmSnappy::Decrypt(const uint8_t* input, uint8_t* output, size_t size, const uint32_t* key)
{
	return XTEA::Decrypt(input, output, size, key, 32);
}

void DefaultAlgorithmSnappy::Encrypt(const uint8_t* input, uint8_t* output, size_t size, const uint32_t* key)
{
	return XTEA::Encrypt(input, output, size, key, 32);
}

bool DefaultAlgorithmSnappy::HaveCryptation()
{
	return true;
}

// ------------------------------------------------------------------------------------------------------------------

namespace DefaultAlgorithms
{
	CryptedObjectAlgorithm* GetDefaultAlgorithm(uint32_t dwFourCC)
	{
		switch (dwFourCC)
		{
		case MAKEFOURCC('M', 'C', 'S', 'P'):
			return new DefaultAlgorithmSnappy();
		case MAKEFOURCC('M', 'C', 'O', 'Z'):
			return new DefaultAlgorithmLzo1x();
		default:
			break;
		}

		return nullptr;
	}

	uint32_t GetFourCC(const uint8_t* pInput)
	{
		const uint32_t* pdwFourCC = reinterpret_cast<const uint32_t*>(pInput);
		return *pdwFourCC;
	}
}
