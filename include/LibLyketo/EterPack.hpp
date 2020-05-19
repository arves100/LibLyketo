/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file EterPack.hpp
	Defines an EterPack Index and Content file
*/
#pragma once

#include <LibLyketo/Interfaces.hpp>

#include <map>
#include <string>
#include <vector>

struct EterPackFile
{
	uint32_t dwId;
	char szFilename[161];
	uint32_t dwFilenameCRC32;
	uint32_t dwRealSize;
	uint32_t dwSize;
	uint32_t dwCRC32;
	uint32_t dwPosition;
	uint8_t bType;

	EterPackFile();
};

class EterPack
{
public:
	EterPack();
	virtual ~EterPack();

	bool Load(const uint8_t* pbInput, size_t nLength, IFileSystem* pcFS);
	bool Create(IFileSystem* pcFSm);

	bool Put(std::string szFile, const uint8_t* pbContent, uint32_t dwContentLen, uint8_t bType);
	bool Save(std::vector<uint8_t>& vOutput);

	const EterPackFile* GetInfo(uint32_t dwCRC32);
	bool Get(std::string szFileName, std::vector<uint8_t>& vData);

protected:
	bool Get(EterPackFile sInfo, std::vector<uint8_t>& vData);

	bool DecryptType(std::vector<uint8_t> vInput, std::vector<uint8_t>& vOutput, uint8_t bType);
	bool EncryptType(const uint8_t* pbInput, uint32_t dwInputLen, std::vector<uint8_t>& vOutput, uint8_t bType);

	IFileSystem* m_pcFS;
	std::map<uint32_t, EterPackFile> m_mFiles;
};
