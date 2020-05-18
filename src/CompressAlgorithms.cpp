#include "CompressAlgorithms.hpp"
#include "lzokay/lzokay.hpp"

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
