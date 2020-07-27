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

CryptedObject::CryptedObject() : m_sHeader(), m_pAlgorithm(nullptr)
{
	memset(m_adwKeys, 0, sizeof(m_adwKeys));
}

CryptedObject::~CryptedObject()
{
	m_pAlgorithm = nullptr;
}

void CryptedObject::SetAlgorithm(std::shared_ptr<CryptedObjectAlgorithm>& pAlgorithm)
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

	m_pBuffer.clear();

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

		m_pBuffer.reserve(m_sHeader.dwRealLength);
		m_pBuffer.resize(m_sHeader.dwRealLength);

		size_t nRealLength = m_sHeader.dwRealLength;
		if (!m_pAlgorithm->Decompress(inputData, m_pBuffer.data(), m_sHeader.dwAfterCompressLength, &nRealLength))
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

		m_pBuffer.reserve(nRealDataLenCalculated);
		m_pBuffer.resize(nRealDataLenCalculated);

		memcpy_s(m_pBuffer.data(), m_pBuffer.size(), pbInput + sizeof(struct CryptedObjectHeader), m_pBuffer.size());
	}

	if (pData)
		delete[] pData;

	return CryptedObjectErrors::Ok;
}

CryptedObjectErrors CryptedObject::Encrypt(const uint8_t* pbInput, size_t nLength, EncryptType sType)
{
	if (!pbInput || nLength < 1)
		return CryptedObjectErrors::InvalidInput;

	m_pBuffer.clear();

	m_sHeader.dwFourCC = m_pAlgorithm->GetFourCC();
	m_sHeader.dwRealLength = static_cast<uint32_t>(nLength);


	// 1. Compress the data
	if (sType != EncryptType::None) {
		size_t nCompressedSize = m_pAlgorithm->GetWrostSize(nLength);
		std::vector<uint8_t> pData(nCompressedSize + sizeof(uint32_t));

		if (!m_pAlgorithm->Compress(pbInput, pData.data(), nLength, &nCompressedSize))
		{
			return CryptedObjectErrors::CompressFail;
		}

		m_sHeader.dwAfterCompressLength = static_cast<uint32_t>(nCompressedSize);

		memcpy_s(pData.data() + sizeof(uint32_t), nCompressedSize, pData.data(), nCompressedSize);
		uint32_t* pnFourCC = reinterpret_cast<uint32_t*>(pData.data());
		*pnFourCC = m_sHeader.dwFourCC;


		// 3. Encrypt data
		if (sType == EncryptType::CompressAndEncrypt && m_pAlgorithm->HaveCryptation())
		{
			m_sHeader.dwAfterCryptLength = m_sHeader.dwAfterCompressLength + 20;

			uint32_t nBufferLen = m_sHeader.dwAfterCryptLength + sizeof(struct CryptedObjectHeader);

			m_pBuffer.reserve(nBufferLen);
			m_pBuffer.resize(nBufferLen);

			m_pAlgorithm->Encrypt(pData.data(), m_pBuffer.data() + sizeof(struct CryptedObjectHeader), m_sHeader.dwAfterCryptLength, m_adwKeys);
		}
		else
		{
			m_sHeader.dwAfterCryptLength = 0;
			uint32_t nBufferLen = m_sHeader.dwAfterCompressLength + sizeof(struct CryptedObjectHeader);

			m_pBuffer.reserve(nBufferLen);
			m_pBuffer.resize(nBufferLen);

			memcpy_s(m_pBuffer.data() + sizeof(struct CryptedObjectHeader), m_pBuffer.size() - sizeof(struct CryptedObjectHeader), pData.data(), nCompressedSize + sizeof(uint32_t));
		}
	}
	else
	{
		m_sHeader.dwAfterCompressLength = 0;
		m_sHeader.dwAfterCryptLength = 0;
	}


	// 4. Store header
	struct CryptedObjectHeader* pHeader = reinterpret_cast<struct CryptedObjectHeader*>(m_pBuffer.data());
	pHeader->dwAfterCompressLength = m_sHeader.dwAfterCompressLength;
	pHeader->dwAfterCryptLength = m_sHeader.dwAfterCryptLength;
	pHeader->dwFourCC = m_sHeader.dwFourCC;
	pHeader->dwRealLength = m_sHeader.dwRealLength;

	return CryptedObjectErrors::Ok;
}
