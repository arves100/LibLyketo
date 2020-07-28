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

enum class ProtoType
{
	MobProto,
	ItemProto,
	ItemProto_Old,
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
	bool Pack(const uint8_t* pCryptBuffer, size_t nLength, ProtoType eType, EncryptType sType = EncryptType::CompressAndEncrypt);

	const uint8_t* GetBuffer() const;
	size_t GetSize() const;
	ProtoType GetType() const { return m_eType; }

	uint32_t GetMobFourCC() { return m_dwFccMobProto; }
	uint32_t GetItemFourCC() { return m_dwFccItemProto; }
	uint32_t GetItemOldFourCC() { return m_dwFccItemProtoOld; }
	uint32_t GetStride() { return m_dwStride; }
	uint32_t GetVersion() { return m_dwVersion; }
	uint32_t GetElements() { return m_dwElements; }
	uint32_t GetCryptedObjectFourCC() { return m_dwCryptedObjectFourCC; }
	uint32_t GetCryptedObjectSize() { return m_dwCryptedObjectSize; }

	void SetVersion(uint32_t dwVersion) { m_dwVersion = dwVersion; }
	void SetMobFourCC(uint32_t dwFcc) { m_dwFccMobProto = dwFcc; }
	void SetItemOldFourCC(uint32_t dwFcc) { m_dwFccItemProtoOld = dwFcc; }
	void SetItemFourCC(uint32_t dwFcc) { m_dwFccItemProto = dwFcc; }

private:
	uint32_t m_dwVersion, m_dwElements, m_dwCryptedObjectSize, m_dwCryptedObjectFourCC, m_dwStride;
	uint32_t m_dwFccItemProto, m_dwFccMobProto, m_dwFccItemProtoOld;

	ProtoType m_eType;

	std::vector<uint8_t> m_pBuffer;
};

#endif // PROTO_HPP
