/* Copyright © 2020 Arves100

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file EterPack.hpp
	Defines an EterPack Index and Content file
*/
#ifndef ETERPACK_HPP
#define ETERPACK_HPP
#pragma once

#include <LibLyketo/IFIleSystem.hpp>

#include <map>
#include <string>
#include <vector>
#include <memory>

#ifdef DecryptFile
#undef DecryptFile
#endif
#ifdef EncryptFile
#undef EncryptFile
#endif

struct EterPackFile
{
	uint32_t dwId;
	char szFilename[161];
	uint8_t bPadding1[3];
	uint32_t dwFilenameCRC32;
	uint32_t dwRealSize;
	uint32_t dwSize;
	uint32_t dwCRC32;
	uint32_t dwPosition;
	uint8_t bType;
	uint8_t bPadding2[3];

	EterPackFile();
};

struct EterPackHeader
{
	uint32_t dwFourCC;
	uint32_t dwVersion;
	uint32_t dwElements;

	EterPackHeader();
};

enum EterPackTypes : uint8_t
{
	Uncompressed = 0,
	CryptedObject_Lzo1x = 1,
	CryptedObject_Lzo1x_Xtea = 2,
	CryptedObject_Snappy = 6,
};

class EterPack
{
public:
	EterPack();
	virtual ~EterPack();

	bool Load(const uint8_t* pbInput, size_t nLength, std::shared_ptr<IFileSystem> pcFS);
	const EterPackFile* GetInfo(uint32_t dwCRC32);
	const EterPackFile* GetInfo(std::string szFileName);

	bool Get(EterPackFile sInfo, const uint32_t* adwKeys = nullptr, uint32_t dwFourcc = 0);

	bool Create(std::shared_ptr<IFileSystem> pcFSm);
	bool Put(std::string szFile, const uint8_t* pbContent, uint32_t dwContentLen, EterPackTypes eType, const uint32_t* adwKeys = nullptr, uint32_t dwFourcc = 0);
	bool Save();

	const uint8_t* GetBuffer() const { return m_pBuffer.data(); }
	size_t GetBufferSize() const { return m_pBuffer.size(); }

	EterPackHeader GetHeader() const { return m_sHeader; }

	void SetVersion(uint32_t dwVersion) { m_sHeader.dwVersion = dwVersion; }
	void SetFourCC(uint32_t dwFcc) { m_sHeader.dwFourCC = dwFcc; }

	std::map<uint32_t, struct EterPackFile> GetFiles() const { return m_mFiles; }

protected:
	bool DecryptFile(const uint8_t* pbInput, uint32_t dwInputLen, uint8_t* pOutput, uint32_t dwOutputLen, EterPackTypes bType, const uint32_t* adwKeys, uint32_t dwFourcc);
	bool EncryptFile(const uint8_t* pbInput, uint32_t dwInputLen, uint8_t* pOutput, uint32_t* dwOutputLen, EterPackTypes bType, const uint32_t* adwKeys, uint32_t dwFourcc);

	std::shared_ptr<IFileSystem> m_pcFS;
	std::map<uint32_t, struct EterPackFile> m_mFiles;
	struct EterPackHeader m_sHeader;

	std::vector<uint8_t> m_pBuffer;
};

#endif // ETERPACK_HPP
