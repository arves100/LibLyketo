/* Copyright © 2020 Arves100

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file CryptedObjectAlgorithm.hpp
	Definition of a generic crypted object algorithm.
*/
#ifndef CRYPTEDOBJECTALGORITHM_HPP
#define CRYPTEDOBJECTALGORITHM_HPP
#pragma once

#include <stdint.h>

/*!
	An abstract class for implementing different compression algorithm used in CryptedObjects.
*/
class CryptedObjectAlgorithm
{
public:
	CryptedObjectAlgorithm() : m_dwFourCC(0) {}

	/*!
		Compress a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it by using @ref GetWrostSize and free the memory of it.

		@param pbInput A buffer that will be encrypted.
		@param pbOutput The output buffer after the encryption.
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false.
	*/
	virtual bool Compress(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) = 0 { return false; }

	/*!
		Decompress a pack of data.

		pbOutput's memory is not managed by this function, make sure to allocate it and free the memory of it.

		@param pbInput A buffer that will be decrypted
		@param pbOutput The output buffer after the decryptation
		@param dwInputLength The length of the input buffer.
		@param pdwOutputLength The resulted size of the output buffer.
		@return true if the decryptation succeeded, otherwise false
	*/
	virtual bool Decompress(const uint8_t* pbInput, uint8_t* pbOutput, size_t dwInputLength, size_t* pdwOutputLength) = 0 { return false; }

	/*!
		Gets the maximum size that could be achieved by encrypting with the selected algorithm.

		@param dwOriginalSize Decrypted size to be computed.
		@return The wrost achievable length with encrypting with this algorithm.
	*/
	virtual size_t GetWrostSize(size_t dwOriginalSize) = 0 { return 0; }

	virtual void Encrypt(const uint8_t* input, uint8_t* output, size_t size, const uint32_t* key) = 0 {}

	virtual uint32_t Decrypt(const uint8_t* input, uint8_t* output, size_t size, const uint32_t* key) = 0 { return 0; }

	virtual bool HaveCryptation() = 0 { return false; }

	void ChangeFourCC(uint32_t dwFourCC) { m_dwFourCC = dwFourCC; }
	uint32_t GetFourCC() { return m_dwFourCC; }

protected:
	uint32_t m_dwFourCC;
};

#endif // CRYPTEDOBJECTALGORITHM_HPP
