/* Copyright © 2020 Arves100

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file CryptedObject.hpp
	Defines a Crypted object format, used in raw EterPack and proto files.
*/
#ifndef CRYPTEDOBJECT_HPP
#define CRYPTEDOBJECT_HPP
#pragma once

#include "ICryptedObjectAlgorithm.hpp"

/*!
	A definition of a CryptedObject.

		- 4 byte FourCC
		- 4 byte Crypted length
		- 4 byte Compressed length
		- 4 byte Real length

		Crypted object: 4 byte FouCC

		Data content
*/
struct CryptedObjectHeader
{
	uint32_t dwFourCC;
	uint32_t dwAfterCryptLength;
	uint32_t dwAfterCompressLength;
	uint32_t dwRealLength;

	CryptedObjectHeader();
};

enum class CryptedObjectErrors
{
	Ok,
	NoMemory,
	InvalidInput,
	InvalidAlgorithm,
	InvalidHeader,
	InvalidCompressLength,
	InvalidRealLength,
	InvalidCryptLength,
	CryptFail,
	InvalidCryptAlgorithm,
	CompressFail,
	InvalidFourCC
};

class CryptedObject
{
public:
	CryptedObject();
	virtual ~CryptedObject();

	CryptedObjectErrors Decrypt(const uint8_t* pbInput, size_t nLength);
	CryptedObjectErrors Encrypt(const uint8_t* pbInput, size_t nLength, bool bEncrypt = true);
	
	const uint8_t* GetBuffer() const { return m_pBuffer; }
	size_t GetSize() const { return m_nBufferLen; }

	void SetKeys(const uint32_t* adwKeys);
	void SetAlgorithm(CryptedObjectAlgorithm* pAlgorithm);

	const uint32_t* GetKeys() const { return m_adwKeys; }
	CryptedObjectAlgorithm* GetAlgorithm() const { return m_pAlgorithm; }

	CryptedObjectHeader GetHeader() const { return m_sHeader; }

private:
	struct CryptedObjectHeader m_sHeader;
	
	uint32_t m_adwKeys[4];
	CryptedObjectAlgorithm* m_pAlgorithm;

	uint8_t* m_pBuffer;
	size_t m_nBufferLen;
};

#endif // CRYPTEDOBJECT_HPP
