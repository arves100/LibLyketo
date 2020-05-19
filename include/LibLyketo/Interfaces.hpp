/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
#pragma once

#include <stdint.h>

/*!
	A generic interface for implementing different compression algorithm used in the CryptedObject format.
*/
class ICompressAlgorithm
{
public:
	/*!
		Encrypts a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it by using @ref GetWrostSize and free the memory of it.

		@param pbInput A buffer that will be encrypted.
		@param pbOutput The output buffer after the encryption.
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false.
	*/
	virtual bool Encrypt(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) = 0 {}

	/*!
		Decrypts a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it and free the memory of it.

		@param pbInput A buffer that will be decrypted
		@param pbOutput The output buffer after the decryptation
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false
	*/
	virtual bool Decrypt(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) = 0 {}

	/*!
		Gets the maximum size that could be achieved by encrypting with the selected algorithm.

		@param dwOriginalSize Decrypted size to be computed.
		@return The wrost achievable length with encrypting with this algorithm.
	*/
	virtual size_t GetWrostSize(size_t dwOriginalSize) = 0 { return 0; }
};

enum class SeekOffset
{
	Start,
	End,
	Current,
};

class IFileSystem
{
public:
	IFileSystem() {}
	virtual ~IFileSystem() {}

	virtual bool Seek(size_t nLength, SeekOffset eOffset) { return false; }
	virtual bool Read(uint8_t* pbOut, size_t nLength) { return false; }
	virtual bool Write(const uint8_t* pbData, size_t nLength) { return false; }
};
