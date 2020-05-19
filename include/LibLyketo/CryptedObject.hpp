/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file CryptedObject.hpp
	Defines a Crypted object format, used in raw EterPack and proto files.
*/
#pragma once

#include <stdint.h>

#include <vector>

/*!
	A definition of a CryptedObject.

		- 4 byte FourCC
		- 4 byte Crypted length
		- 4 byte Compressed length
		- 4 byte Real length

		Crypted object: 4 byte FouCC

		Data content
*/
class CryptedObject
{
public:
	CryptedObject();
	virtual ~CryptedObject();

	bool Decrypt(const uint8_t* pbInput, size_t nLength, const uint32_t adwKeys[]);
	bool Encrypt(const uint8_t* pbInput, size_t nLength, const uint32_t adwKeys[]);
	
	const uint8_t* GetBuffer() { return m_vBuffer.data(); }
	size_t GetSize() { return m_vBuffer.size(); }

private:
	uint32_t m_dwFourCC;
	uint32_t m_dwAfterCryptLength;
	uint32_t m_dwAfterCompressLength;
	uint32_t m_dwRealLength;

	std::vector<uint8_t> m_vBuffer;
};
