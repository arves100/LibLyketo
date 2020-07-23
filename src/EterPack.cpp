/* Copyright © 2020 Arves100

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file EterPack.cpp
	Implements an EterPack Index and Content file
*/
#include <LibLyketo/DefaultAlgorithms.hpp>
#include <LibLyketo/EterPack.hpp>
#include <LibLyketo/CryptedObject.hpp>

#include <crc32/Crc32.h>

#include <time.h>
#include <string.h>
#include <algorithm>

#define MAKEFOURCC(ch0, ch1, ch2, ch3) ((uint32_t)(uint8_t)(ch0) | ((uint32_t)(uint8_t)(ch1) << 8) | ((uint32_t)(uint8_t)(ch2) << 16) | ((uint32_t)(uint8_t)(ch3) << 24))

EterPackFile::EterPackFile() : dwId(0), dwFilenameCRC32(0), dwRealSize(0), dwSize(0), dwCRC32(0), dwPosition(0), bType(0)
{
	memset(szFilename, 0, sizeof(szFilename));
	memset(bPadding1, 0, sizeof(bPadding1));
	memset(bPadding2, 0, sizeof(bPadding2));
}

EterPackHeader::EterPackHeader() : dwFourCC(MAKEFOURCC('E', 'P', 'K', 'D')), dwVersion(2), dwElements(0) {}

EterPack::EterPack() : m_pcFS(nullptr), m_sHeader(), m_pBuffer(nullptr), m_nBufferSize(0), m_dwSnappyFourCC(MAKEFOURCC('M', 'C', 'S', 'P')), m_dwLzoFourCC(MAKEFOURCC('M','C','O','Z'))
{
	memset(m_dwEpkKeys, 0, sizeof(m_dwEpkKeys));
}

EterPack::~EterPack()
{
	if (m_pBuffer)
		delete[] m_pBuffer;

	m_pBuffer = nullptr;
}

bool EterPack::Load(const uint8_t* pbInput, size_t nLength, IFileSystem* pcFS)
{
	if (!pbInput || nLength < 12)
		return false;

	const struct EterPackHeader* pHeader = reinterpret_cast<const struct EterPackHeader*>(pbInput);

	if (pHeader->dwFourCC != m_sHeader.dwFourCC)
		return false;

	if (pHeader->dwVersion != m_sHeader.dwVersion)
		return false;

	if (pHeader->dwElements < 1)
		return true;

	m_sHeader.dwElements = pHeader->dwElements;

	if ((m_sHeader.dwElements * sizeof(struct EterPackFile)) != (nLength - sizeof(struct EterPackHeader)))
		return false;

	m_mFiles.clear();

	size_t nOffset = sizeof(struct EterPackHeader);
	for (uint32_t i = 0; i < m_sHeader.dwElements; i++)
	{
		EterPackFile epf = *reinterpret_cast<const struct EterPackFile*>(pbInput + nOffset);

		uint32_t dwCalcCrc = crc32_fast(epf.szFilename, strlen(epf.szFilename));

		if (dwCalcCrc != epf.dwFilenameCRC32)
			continue;

		// Map by Filename CRC32
		m_mFiles[epf.dwFilenameCRC32] = epf;
	}

	m_pcFS = pcFS;

	return true;
}

bool EterPack::Create(IFileSystem* pcFS)
{
	m_mFiles.clear();
	m_pcFS = pcFS;
	return true;
}

const EterPackFile* EterPack::GetInfo(uint32_t dwCRC32)
{
	auto it = m_mFiles.find(dwCRC32);
	if (it == m_mFiles.end())
		return nullptr;

	return &it->second;
}

bool EterPack::Get(EterPackFile sInfo)
{
	if (!m_pcFS->Seek(sInfo.dwPosition, SeekOffset::Start))
		return false;

	if (m_pBuffer)
		delete[] m_pBuffer;

	uint8_t* cData = new uint8_t[sInfo.dwSize];

	if (!cData)
		return false;

	m_pBuffer = new uint8_t[sInfo.dwRealSize];
	if (!m_pBuffer)
	{
		delete[] cData;
		return false;
	}

	m_nBufferSize = sInfo.dwRealSize;

	if (!m_pcFS->Read(cData, sInfo.dwSize))
	{
		delete[] cData;
		delete[] m_pBuffer;
		m_pBuffer = nullptr;
		return false;
	}

	bool r = DecryptFile(cData, sInfo.dwSize, m_pBuffer, sInfo.dwRealSize, static_cast<EterPackTypes>(sInfo.bType));

	delete[] cData;

	if (!r)
	{
		delete[] m_pBuffer;
		m_pBuffer = nullptr;
		return false;
	}

	return true;
}

bool EterPack::Get(std::string szFileName)
{
	if (szFileName.length() < 1)
		return false;

	std::transform(szFileName.begin(), szFileName.end(), szFileName.begin(), ::tolower);

	uint32_t dwCRC = crc32_fast(szFileName.data(), szFileName.size() + 1);

	auto info = GetInfo(dwCRC);

	if (!info)
		return false;

	return Get(*info);
}

bool EterPack::DecryptFile(const uint8_t* pbInput, uint32_t dwInputLen, uint8_t* pOutput, uint32_t dwOutputLen, EterPackTypes bType)
{
	if (!pbInput || !pOutput || dwInputLen < 1 || dwOutputLen < 1)
		return false;

	if (bType == Uncompressed) // Raw
	{
		if (dwInputLen != dwOutputLen)
			return false;

		memcpy_s(pOutput, dwOutputLen, pbInput, dwInputLen);
		return true;
	}
	else if (bType == CryptedObject_Lzo1x || bType == CryptedObject_Snappy) // Crypted object
	{
		CryptedObject obj;

		obj.SetKeys(m_dwEpkKeys);
		
		CryptedObjectAlgorithm* pAlgorithm = nullptr;

		if (bType == CryptedObject_Snappy)
		{
			pAlgorithm = new DefaultAlgorithmSnappy();
			pAlgorithm->ChangeFourCC(m_dwSnappyFourCC);
		}
		else
		{
			pAlgorithm = new DefaultAlgorithmLzo1x();
			pAlgorithm->ChangeFourCC(m_dwLzoFourCC);
		}

		if (obj.Decrypt(pbInput, dwInputLen) != CryptedObjectErrors::Ok)
		{
			delete pAlgorithm;
			return false;
		}

		delete pAlgorithm;

		if (obj.GetSize() != dwOutputLen)
			return false;

		memcpy_s(pOutput, dwOutputLen, obj.GetBuffer(), obj.GetSize());
		return true;
	}

	// §TODO

	return false;
}

bool EterPack::EncryptFile(const uint8_t* pbInput, uint32_t dwInputLen, uint8_t* pOutput, uint32_t* dwOutputLen, EterPackTypes bType)
{
	if (bType == Uncompressed) // Raw
	{
		*dwOutputLen = dwInputLen;
		pOutput = new uint8_t[dwInputLen];

		if (!pOutput)
			return false;

		memcpy_s(pOutput, dwInputLen, pbInput, dwInputLen);
		return true;
	}
	else if (bType == CryptedObject_Lzo1x || bType == CryptedObject_Snappy) // Crypted object
	{
		CryptedObject obj;

		obj.SetKeys(m_dwEpkKeys);

		CryptedObjectAlgorithm* pAlgorithm = nullptr;

		if (bType == CryptedObject_Snappy)
		{
			pAlgorithm = new DefaultAlgorithmSnappy();
			pAlgorithm->ChangeFourCC(m_dwSnappyFourCC);
		}
		else
		{
			pAlgorithm = new DefaultAlgorithmLzo1x();
			pAlgorithm->ChangeFourCC(m_dwLzoFourCC);
		}

		if (obj.Encrypt(pbInput, dwInputLen) != CryptedObjectErrors::Ok)
			return false;

		*dwOutputLen = static_cast<uint32_t>(obj.GetSize());

		pOutput = new uint8_t[obj.GetSize()];
		if (!pOutput)
			return false;

		memcpy_s(pOutput, obj.GetSize(), obj.GetBuffer(), obj.GetSize());
		return true;	
	}

	// §TODO

	return false;
}

bool EterPack::Save()
{
	srand(static_cast<unsigned int>(time(0)));

	if (m_pBuffer)
		delete[] m_pBuffer;

	m_sHeader.dwElements = static_cast<uint32_t>(m_mFiles.size());

	m_nBufferSize = (sizeof(struct EterPackFile) * m_sHeader.dwElements) + sizeof(struct EterPackHeader);
	m_pBuffer = new uint8_t[m_nBufferSize];

	auto it = m_mFiles.begin(), end = m_mFiles.end();
	for (size_t i = 0; i < m_sHeader.dwElements; i++, it++)
	{
		if (it == end)
			break;

		auto info = it->second;

		// Padding
		info.bPadding1[0] = rand() & 0xFF;
		info.bPadding1[1] = rand() & 0xFF;
		info.bPadding1[2] = rand() & 0xFF;
		info.bPadding2[0] = rand() & 0xFF;
		info.bPadding2[1] = rand() & 0xFF;
		info.bPadding2[2] = rand() & 0xFF;

		memcpy_s(m_pBuffer + sizeof(struct EterPackHeader) + (i * sizeof(struct EterPackFile)), sizeof(struct EterPackFile), &info, sizeof(info));
	}

	memcpy_s(m_pBuffer, m_nBufferSize, &m_sHeader, sizeof(m_sHeader));
	return true;
}

bool EterPack::Put(std::string szFile, const uint8_t* pbContent, uint32_t dwContentLen, EterPackTypes bType)
{
	uint32_t dwLength = 0;
	uint8_t* pData = nullptr;

	if (!EncryptFile(pbContent, dwContentLen, pData, &dwLength, bType))
		return false;

	if (!m_pcFS->Write(pData, dwLength))
	{
		delete[] pData;
		return false;
	}

	EterPackFile epf;
	epf.dwFilenameCRC32 = crc32_fast(szFile.c_str(), szFile.size());
	epf.bType = bType;
	epf.dwRealSize = dwContentLen;
	epf.dwId = static_cast<uint32_t>(m_mFiles.size());
	epf.dwSize = dwLength;
	strncpy_s(epf.szFilename, _countof(epf.szFilename), szFile.c_str(), 160);
	epf.dwCRC32 = crc32_fast(pData, dwLength);
	epf.dwPosition = static_cast<uint32_t>(m_pcFS->Tell() - dwLength);

	m_mFiles[epf.dwCRC32] = epf;

	return true;
}
