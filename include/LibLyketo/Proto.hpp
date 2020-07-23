/* Copyright © 2020 Arves100

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file Proto.hpp
	Defines an Item or Mob Proto format.
*/
#ifndef PROTO_HPP
#define PROTO_HPP
#pragma once

#include "CryptedObject.hpp"

#include <memory>

enum class ProtoType
{
	MobProto,
	ItemProto,
	ItemProto_Old,
};

struct ItemProtoHeaderNew
{
	uint32_t dwFourCC;
	uint32_t dwVersion;
	uint32_t dwStride;
	uint32_t dwElements;
	uint32_t dwCryptedObjectSize;

	ItemProtoHeaderNew();
};

struct MobProtoHeader
{
	uint32_t dwFourCC;
	uint32_t dwElements;
	uint32_t dwCryptedObjectSize;

	MobProtoHeader();
};

struct ItemProtoHeaderOld
{
	uint32_t dwFourCC;
	uint32_t dwElements;
	uint32_t dwCryptedObjectSize;

	ItemProtoHeaderOld();
};

/*!
	A class that supports Item or Mob Proto format.
*/
class Proto
{
public:
	Proto();
	virtual ~Proto();

	bool Unpack(const uint8_t* pbInput, size_t nLength);

	bool Create(ProtoType eType, uint32_t dwElements);
	bool Pack(const uint8_t* pbInput, size_t nLength, bool bEncrypt = true);

	void SetKeys(const uint32_t* adwKeys);
	void SetAlgorithm(CryptedObjectAlgorithm* pAlgorithm);

	void SetItemProtoVersion(uint32_t dwVersion) { m_sItemProtoNew.dwVersion = dwVersion; }
	void SetItemProtoStride(uint32_t dwStride) { m_sItemProtoNew.dwStride = dwStride; }
	void SetItemProtoNewFourCC(uint32_t dwFourCC) { m_sItemProtoNew.dwFourCC = dwFourCC; }
	void SetItemProtoOldFourCC(uint32_t dwFourCC) { m_sItemProtoOld.dwFourCC = dwFourCC; }
	void SetMobProtoFourCC(uint32_t dwFourCC) { m_sMobProto.dwFourCC = dwFourCC; }

	const uint8_t* GetBuffer() const;
	size_t GetSize() const;
	ProtoType GetType() const { return m_eType; }

	struct ItemProtoHeaderNew GetItemProtoNewHeader() const { return m_sItemProtoNew; }
	struct ItemProtoHeaderOld GetItemProtoOldHeader() const { return m_sItemProtoOld; }
	struct MobProtoHeader GetMobProtoHeader() const { return m_sMobProto; }

private:
	ItemProtoHeaderOld m_sItemProtoOld;
	MobProtoHeader m_sMobProto;
	ItemProtoHeaderNew m_sItemProtoNew;

	ProtoType m_eType;
	std::unique_ptr<CryptedObject> m_upObject;

	uint8_t* m_pBuffer;
	size_t m_nBufferLen;
};

#endif // PROTO_HPP
