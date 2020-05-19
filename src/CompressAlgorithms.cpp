/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "CompressAlgorithms.hpp"
#include <lzokay/lzokay.hpp>
#include <snappy.h>

// LZO (MCOZ)
bool CompressAlgorithmLzo1x::Encrypt(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength)
{
	if (!pbOutput || !pbInput || dwInputLength < 1 || !pdwOutputLength || *pdwOutputLength < 1)
		return false;

	size_t zOutSize;
	auto r = lzokay::compress(pbInput, dwInputLength, pbOutput, *pdwOutputLength, zOutSize);
	*pdwOutputLength = static_cast<uint32_t>(zOutSize);
	return r == lzokay::EResult::Success;
}

bool CompressAlgorithmLzo1x::Decrypt(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength)
{
	if (!pbOutput || !pbInput || dwInputLength < 1 || !pdwOutputLength || *pdwOutputLength < 1)
		return false;

	size_t zOutSize;
	auto r = lzokay::decompress(pbInput, dwInputLength, pbOutput, *pdwOutputLength, zOutSize);

	*pdwOutputLength = static_cast<uint32_t>(zOutSize);
	return r == lzokay::EResult::Success;
}

size_t CompressAlgorithmLzo1x::GetWrostSize(size_t dwOriginalSize)
{
	return lzokay::compress_worst_size(dwOriginalSize);
}
// ------------------------------------------------------------------------------------------------------------------

// Snappy (MCPS)
bool CompressAlgorithmSnappy::Encrypt(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength)
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

bool CompressAlgorithmSnappy::Decrypt(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength)
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

size_t CompressAlgorithmSnappy::GetWrostSize(size_t dwOriginalSize)
{
	return snappy::MaxCompressedLength(dwOriginalSize);
}
// ------------------------------------------------------------------------------------------------------------------
