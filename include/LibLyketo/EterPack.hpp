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
	Uncompressed,
	Compress_Lzo,
	CryptedObject_Lzo1x,
	Parama,
	HybridCrypt,
	HybridCrypt2,
	CryptedObject_Snappy,
};

class EterPack
{
public:
	EterPack();
	virtual ~EterPack();

	bool Load(const uint8_t* pbInput, size_t nLength, IFileSystem* pcFS);
	const EterPackFile* GetInfo(uint32_t dwCRC32);
	bool Get(std::string szFileName);

	bool Create(IFileSystem* pcFSm);
	bool Put(std::string szFile, const uint8_t* pbContent, uint32_t dwContentLen, EterPackTypes eType);
	bool Save();

	const uint8_t* GetBuffer() const { return m_pBuffer; }
	size_t GetBufferSize() const { return m_nBufferSize; }

	void SetSnappyFourCC(uint32_t dwFcc) { m_dwSnappyFourCC = dwFcc; }
	void SetLzo1xFourCC(uint32_t dwFcc) { m_dwLzoFourCC = dwFcc; }

protected:
	bool Get(EterPackFile sInfo);

	bool DecryptFile(const uint8_t* pbInput, uint32_t dwInputLen, uint8_t* pOutput, uint32_t dwOutputLen, EterPackTypes bType);
	bool EncryptFile(const uint8_t* pbInput, uint32_t dwInputLen, uint8_t* pOutput, uint32_t* dwOutputLen, EterPackTypes bType);

	IFileSystem* m_pcFS;
	std::map<uint32_t, struct EterPackFile> m_mFiles;
	struct EterPackHeader m_sHeader;

	uint8_t* m_pBuffer;
	size_t m_nBufferSize;

	uint32_t m_dwEpkKeys[4];

	uint32_t m_dwSnappyFourCC, m_dwLzoFourCC;
};

#endif // ETERPACK_HPP
