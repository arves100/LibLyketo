/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file EterPack.cpp
	Defines an EterPack Index and Content file
*/

#include <LibLyketo/EterPack.hpp>
#include <LibLyketo/Config.hpp>
#include <crc32/Crc32.h>
#include "Utility.hpp"

#include <string.h>
#include <algorithm>

EterPackFile::EterPackFile() : dwId(0), dwFilenameCRC32(0), dwRealSize(0), dwSize(0), dwCRC32(0), dwPosition(0), bType(0)
{
	memset(szFilename, 0, sizeof(szFilename));
}

EterPack::EterPack() : m_pcFS(nullptr)
{
}

EterPack::~EterPack()
{
}

bool EterPack::Load(const uint8_t* pbInput, size_t nLength, IFileSystem* pcFS)
{
	if (!pbInput || nLength < 12)
		return false;

	if (Utility::FromByteArray(pbInput) != Config::Instance()->EterPack().dwFourCC)
		return false;

	if (Utility::FromByteArray(pbInput + 4) != Config::Instance()->EterPack().dwVersion)
		return false;

	uint32_t dwElements = Utility::FromByteArray(pbInput + 8);

	if (dwElements < 1)
		return true;

	if ((dwElements * 192) != (nLength - 12))
		return false;

	m_mFiles.clear();

	size_t nOffset = 12;
	for (uint32_t i = 0; i < dwElements; i++)
	{
		EterPackFile epf;
		epf.dwId = Utility::FromByteArray(pbInput + nOffset);
		nOffset += 4;
		strncpy_s(epf.szFilename, _countof(epf.szFilename), reinterpret_cast<const char*>(pbInput + nOffset), 161);
		nOffset += 164; // 3 padding
		epf.dwFilenameCRC32 = Utility::FromByteArray(pbInput + nOffset);

		uint32_t dwCalcCrc = crc32_fast(epf.szFilename, strlen(epf.szFilename));

		if (dwCalcCrc != epf.dwFilenameCRC32)
			continue;

		epf.dwRealSize = Utility::FromByteArray(pbInput + nOffset);
		nOffset += 4;
		epf.dwSize = Utility::FromByteArray(pbInput + nOffset);
		nOffset += 4;
		epf.dwCRC32 = Utility::FromByteArray(pbInput + nOffset);
		nOffset += 4;
		epf.dwPosition = Utility::FromByteArray(pbInput + nOffset);
		nOffset += 4;
		epf.bType = *(pbInput + nOffset);
		nOffset += 4; // 3 padding

		// Map then by Filename CRC32
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

bool EterPack::Get(EterPackFile sInfo, std::vector<uint8_t>& vData)
{
	if (!m_pcFS->Seek(sInfo.dwPosition, SeekOffset::Start))
		return false;

	std::vector<uint8_t> data;
		
	data.reserve(sInfo.dwSize);
	data.resize(sInfo.dwSize);

	if (!m_pcFS->Read(data.data(), sInfo.dwSize))
		return false;

	vData.reserve(sInfo.dwRealSize);
	vData.resize(sInfo.dwRealSize);

	return DecryptType(data, vData, sInfo.bType);
}

bool EterPack::Get(std::string szFileName, std::vector<uint8_t>& vData)
{
	if (szFileName.length() < 1)
		return false;

	std::transform(szFileName.begin(), szFileName.end(), szFileName.begin(), ::tolower);

	uint32_t dwCRC = crc32_fast(szFileName.data(), szFileName.size() + 1);

	auto info = GetInfo(dwCRC);

	if (!info)
		return false;

	return Get(*info, vData);
}

bool EterPack::DecryptType(std::vector<uint8_t> vInput, std::vector<uint8_t>& vOutput, uint8_t bType)
{
	if (bType == 0) // Raw
	{
		if (vOutput.size() != vInput.size())
			return false;

		memcpy_s(vOutput.data(), vOutput.size(), vInput.data(), vInput.size());
	}

	return false;
}
