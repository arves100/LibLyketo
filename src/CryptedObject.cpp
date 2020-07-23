/* Copyright © 2020 Arves100

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file CryptedObject.cpp
	Implements a Crypted object format, used in raw EterPack and proto files.
*/
#include <LibLyketo/CryptedObject.hpp>

#include <string.h>

CryptedObjectHeader::CryptedObjectHeader() : dwFourCC(0), dwAfterCryptLength(0), dwAfterCompressLength(0), dwRealLength(0) {}

CryptedObject::CryptedObject() : m_sHeader(), m_pAlgorithm(nullptr), m_pBuffer(nullptr), m_nBufferLen(0)
{
	memset(m_adwKeys, 0, sizeof(m_adwKeys));
}

CryptedObject::~CryptedObject()
{
	if (m_pBuffer)
		delete[] m_pBuffer;

	m_pBuffer = nullptr;
	m_pAlgorithm = nullptr;
}

void CryptedObject::SetAlgorithm(ICryptedObjectAlgorithm* pAlgorithm)
{
	m_pAlgorithm = pAlgorithm;
}

void CryptedObject::SetKeys(const uint32_t* adwKeys)
{
	memcpy_s(m_adwKeys, sizeof(m_adwKeys), adwKeys, 16);
}

CryptedObjectErrors CryptedObject::Decrypt(const uint8_t* pbInput, size_t nLength)
{
	if (!pbInput || nLength < (sizeof(struct CryptedObjectHeader) + sizeof(uint32_t)))
		return CryptedObjectErrors::InvalidInput;

	if (!m_pAlgorithm)
		return CryptedObjectErrors::InvalidAlgorithm;

	if (m_pBuffer)
		delete[] m_pBuffer;

	m_pBuffer = nullptr;

	m_sHeader = *(struct CryptedObjectHeader*)(pbInput);

	uint8_t* pData = nullptr;

	if (m_sHeader.dwRealLength < 1 || m_sHeader.dwFourCC != m_pAlgorithm->GetFourCC())
	{
		return CryptedObjectErrors::InvalidHeader;
	}

	// 1. Decrypt the data
	if (m_sHeader.dwAfterCryptLength > 0)
	{
		if ((nLength - sizeof(struct CryptedObjectHeader) - sizeof(uint32_t)) != m_sHeader.dwAfterCryptLength) // Header + fourcc
		{
			return CryptedObjectErrors::InvalidCryptLength;
		}
		
		pData = new uint8_t[m_sHeader.dwAfterCompressLength + 20]; // +20 -.-''

		if (!pData)
		{
			return CryptedObjectErrors::NoMemory;
		}

		m_pAlgorithm->Decrypt(pbInput + sizeof(struct CryptedObjectHeader), pData, m_sHeader.dwAfterCryptLength, m_adwKeys);

		if (*reinterpret_cast<uint32_t*>(pData) != m_sHeader.dwFourCC) // Verify decryptation
		{
			delete[] pData;
			return CryptedObjectErrors::CryptFail;
		}
	}

	// 2. Decompress the data
	if (m_sHeader.dwAfterCompressLength > 0)
	{
		if (!m_pAlgorithm->HaveCryptation())
		{
			if (pData)
				delete[] pData;

			return CryptedObjectErrors::InvalidCryptAlgorithm;
		}

		const uint8_t* inputData = nullptr;

		if (m_sHeader.dwAfterCryptLength < 1) // Data is not encrypted
		{
			if (pData)
				delete[] pData;

			if ((nLength - sizeof(struct CryptedObjectHeader)) != m_sHeader.dwAfterCompressLength)
				return CryptedObjectErrors::InvalidCompressLength;

			pData = new uint8_t[m_sHeader.dwAfterCompressLength + sizeof(uint32_t)];

			if (!pData)
				return CryptedObjectErrors::NoMemory;

			memcpy_s(pData, m_sHeader.dwAfterCompressLength, pbInput + sizeof(struct CryptedObjectHeader), m_sHeader.dwAfterCompressLength);

			if (*reinterpret_cast<uint32_t*>(pData) != m_sHeader.dwFourCC) // Verify decryptation
			{
				delete[] pData;
				return CryptedObjectErrors::InvalidFourCC;
			}
		}

		inputData = pData + sizeof(uint32_t);

		m_nBufferLen = m_sHeader.dwRealLength;
		m_pBuffer = new uint8_t[m_nBufferLen];

		size_t nRealLength = m_sHeader.dwRealLength;
		if (!m_pAlgorithm->Decompress(inputData, m_pBuffer, m_sHeader.dwAfterCompressLength, &nRealLength))
		{
			delete[] pData;
			return CryptedObjectErrors::CompressFail;
		}

		if (nRealLength != m_sHeader.dwRealLength)
		{
			delete[] pData;
			return CryptedObjectErrors::InvalidRealLength;
		}
	}
	else
	{
		if (m_sHeader.dwAfterCompressLength > 0)
		{
			if (pData)
				delete[] pData;

			return CryptedObjectErrors::Ok;
		}

		// Data is not compressed at all

		size_t nRealDataLenCalculated = nLength - sizeof(struct CryptedObjectHeader);

		if (nRealDataLenCalculated != m_sHeader.dwRealLength)
		{
			if (pData)
				delete[] pData;

			return CryptedObjectErrors::InvalidRealLength;
		}

		m_nBufferLen = nRealDataLenCalculated;
		m_pBuffer = new uint8_t[m_nBufferLen];

		memcpy_s(m_pBuffer, m_nBufferLen, pbInput + sizeof(struct CryptedObjectHeader), m_nBufferLen);
	}

	if (pData)
		delete[] pData;

	return CryptedObjectErrors::Ok;
}

CryptedObjectErrors CryptedObject::Encrypt(const uint8_t* pbInput, size_t nLength, bool bEncrypt)
{
	// §NOTE: No support for uncompressed crypted objects

	if (!pbInput || nLength < 1)
		return CryptedObjectErrors::InvalidInput;


	if (m_pBuffer)
		delete[] m_pBuffer;

	m_pBuffer = nullptr;

	m_sHeader.dwFourCC = m_pAlgorithm->GetFourCC();
	m_sHeader.dwRealLength = static_cast<uint32_t>(nLength);

	size_t nCompressedSize = m_pAlgorithm->GetWrostSize(nLength);

	uint8_t* pData = new uint8_t[nCompressedSize + sizeof(uint32_t)];

	if (!pData)
	{
		return CryptedObjectErrors::NoMemory;
	}

	// 1. Compress the data
	if (!m_pAlgorithm->Compress(pbInput, pData, nLength, &nCompressedSize))
	{
		delete[] pData;
		return CryptedObjectErrors::CompressFail;
	}

	m_sHeader.dwAfterCompressLength = static_cast<uint32_t>(nCompressedSize);

	memcpy_s(pData + sizeof(uint32_t), nCompressedSize, pData, nCompressedSize);
	uint32_t* pnFourCC = reinterpret_cast<uint32_t*>(pData);
	*pnFourCC = m_sHeader.dwFourCC;

	// 3. Encrypt data
	if (bEncrypt && m_pAlgorithm->HaveCryptation())
	{
		m_sHeader.dwAfterCryptLength = m_sHeader.dwAfterCompressLength + 20;
		m_nBufferLen = m_sHeader.dwAfterCryptLength + sizeof(struct CryptedObjectHeader);
		m_pBuffer = new uint8_t[m_nBufferLen];

		if (!m_pBuffer)
		{
			delete[] pData;
			return CryptedObjectErrors::NoMemory;
		}

		m_pAlgorithm->Encrypt(pData, m_pBuffer + sizeof(struct CryptedObjectHeader), m_sHeader.dwAfterCryptLength, m_adwKeys);
	}
	else
	{
		m_sHeader.dwAfterCryptLength = 0;
		m_nBufferLen = m_sHeader.dwAfterCompressLength + sizeof(struct CryptedObjectHeader);
		m_pBuffer = new uint8_t[m_nBufferLen];

		if (!m_pBuffer)
		{
			delete[] pData;
			return CryptedObjectErrors::NoMemory;
		}

		memcpy_s(m_pBuffer + sizeof(struct CryptedObjectHeader), m_nBufferLen - sizeof(struct CryptedObjectHeader), pData, nCompressedSize + sizeof(uint32_t));
	}


	// 4. Store header
	struct CryptedObjectHeader* pHeader = reinterpret_cast<struct CryptedObjectHeader*>(m_pBuffer);
	pHeader->dwAfterCompressLength = m_sHeader.dwAfterCompressLength;
	pHeader->dwAfterCryptLength = m_sHeader.dwAfterCryptLength;
	pHeader->dwFourCC = m_sHeader.dwFourCC;
	pHeader->dwRealLength = m_sHeader.dwRealLength;

	delete[] pData;

	return CryptedObjectErrors::Ok;
}
