/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file CompressAlgorithms.hpp
	Definition of multiple algorithms that works with a CryptedObject.
*/
#pragma once

#include <LibLyketo/Interfaces.hpp>

/*!
	Implementation of ICompressAlgorithm with Lzo1x
*/
class CompressAlgorithmLzo1x : public ICompressAlgorithm
{
public:
	/*!
		Encrypts a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it by using @ref GetWrostSize and free the memory of it.
		Make sure to set pdwOutputLength content to the size of the pbOutput buffer otherwise the function will fail.

		@param pbInput A buffer that will be encrypted.
		@param pbOutput The output buffer after the encryption.
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false.
	*/
	bool Encrypt(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) override;

	/*!
		Decrypts a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it and free the memory of it.
		Make sure to set pdwOutputLength content to the size of the pbOutput buffer otherwise the function will fail.

		@param pbInput A buffer that will be decrypted
		@param pbOutput The output buffer after the decryptation.
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false
	*/
	bool Decrypt(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) override;

	/*!
		Gets the maximum size that could be achieved by encrypting with the selected algorithm.

		@param dwOriginalSize Decrypted size to be computed.
		@return The wrost achievable length with encrypting with this algorithm.
	*/
	size_t GetWrostSize(size_t dwOriginalSize) override;
};


/*!
	Implementation of ICompressAlgorithm with Snappy
*/
class CompressAlgorithmSnappy : public ICompressAlgorithm
{
public:
	/*!
		Encrypts a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it by using @ref GetWrostSize and free the memory of it.
		Make sure to set pdwOutputLength content to the size of the pbOutput buffer otherwise the function will fail.

		@param pbInput A buffer that will be encrypted.
		@param pbOutput The output buffer after the encryption.
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false.
	*/
	bool Encrypt(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) override;

	/*!
		Decrypts a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it and free the memory of it.
		Make sure to set pdwOutputLength content to the size of the pbOutput buffer otherwise the function will fail.

		@param pbInput A buffer that will be decrypted
		@param pbOutput The output buffer after the decryptation.
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false
	*/
	bool Decrypt(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) override;

	/*!
		Gets the maximum size that could be achieved by encrypting with the selected algorithm.

		@param dwOriginalSize Decrypted size to be computed.
		@return The wrost achievable length with encrypting with this algorithm.
	*/
	size_t GetWrostSize(size_t dwOriginalSize) override;
};
