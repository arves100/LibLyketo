/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file DefaultAlgorithms.hpp
	Definition of the default algorithms that works with a CryptedObject.
*/
#ifndef DEFAULTALGORITHMS_HPP
#define DEFAULTALGORITHMS_HPP
#pragma once

#include <LibLyketo/ICryptedObjectAlgorithm.hpp>

/*!
	Implementation of ICompressAlgorithm with Lzo1x
*/
class DefaultAlgorithmLzo1x : public CryptedObjectAlgorithm
{
public:
	DefaultAlgorithmLzo1x();

	/*!
		Compress a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it by using @ref GetWrostSize and free the memory of it.
		Make sure to set pdwOutputLength content to the size of the pbOutput buffer otherwise the function will fail.

		@param pbInput A buffer that will be encrypted.
		@param pbOutput The output buffer after the encryption.
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false.
	*/
	bool Compress(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) override;

	/*!
		Decompress a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it and free the memory of it.
		Make sure to set pdwOutputLength content to the size of the pbOutput buffer otherwise the function will fail.

		@param pbInput A buffer that will be decrypted
		@param pbOutput The output buffer after the decryptation.
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false
	*/
	bool Decompress(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) override;

	/*!
		Gets the maximum size that could be achieved by encrypting with the selected algorithm.

		@param dwOriginalSize Decrypted size to be computed.
		@return The wrost achievable length with encrypting with this algorithm.
	*/
	size_t GetWrostSize(size_t dwOriginalSize) override;

	

	bool HaveCryptation() override;

	uint32_t Decrypt(const uint8_t* input, uint8_t* output, size_t size, const uint32_t* key) override;
	void Encrypt(const uint8_t* input, uint8_t* output, size_t size, const uint32_t* key) override;

};

/*!
	Implementation of ICompressAlgorithm with Snappy
*/
class DefaultAlgorithmSnappy : public CryptedObjectAlgorithm
{
public:
	DefaultAlgorithmSnappy();

	/*!
		Compress a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it by using @ref GetWrostSize and free the memory of it.
		Make sure to set pdwOutputLength content to the size of the pbOutput buffer otherwise the function will fail.

		@param pbInput A buffer that will be encrypted.
		@param pbOutput The output buffer after the encryption.
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false.
	*/
	bool Compress(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) override;

	/*!
		Decompress a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it and free the memory of it.
		Make sure to set pdwOutputLength content to the size of the pbOutput buffer otherwise the function will fail.

		@param pbInput A buffer that will be decrypted
		@param pbOutput The output buffer after the decryptation.
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false
	*/
	bool Decompress(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) override;

	/*!
		Gets the maximum size that could be achieved by encrypting with the selected algorithm.

		@param dwOriginalSize Decrypted size to be computed.
		@return The wrost achievable length with encrypting with this algorithm.
	*/
	size_t GetWrostSize(size_t dwOriginalSize) override;

	bool HaveCryptation() override;
	uint32_t Decrypt(const uint8_t* input, uint8_t* output, size_t size, const uint32_t* key) override;
	void Encrypt(const uint8_t* input, uint8_t* output, size_t size, const uint32_t* key) override;
};

namespace DefaultAlgorithms
{
	CryptedObjectAlgorithm* GetDefaultAlgorithm(uint32_t dwFourCC);
	uint32_t GetFourCC(const uint8_t* pInput);
}

#endif // DEFAULTALGORITHMS_HPP
