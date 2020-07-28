/* Copyright © 2020 Arves100

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file Proto.cpp
	Defines an Item or Mob Proto format.
*/
#include <LibLyketo/Proto.hpp>

#define MAKEFOURCC(ch0, ch1, ch2, ch3) ((uint32_t)(uint8_t)(ch0) | ((uint32_t)(uint8_t)(ch1) << 8) | ((uint32_t)(uint8_t)(ch2) << 16) | ((uint32_t)(uint8_t)(ch3) << 24))

Proto::Proto() : m_dwVersion(2), m_dwElements(0), m_dwCryptedObjectSize(0), m_dwCryptedObjectFourCC(0), m_dwStride(156), m_dwFccItemProto(MAKEFOURCC('M', 'I', 'P', 'X')), m_dwFccMobProto(MAKEFOURCC('M', 'M', 'P', 'T')), m_dwFccItemProtoOld(MAKEFOURCC('M', 'I', 'P', 'T')), m_eType(ProtoType::MobProto)
{

}

Proto::~Proto()
{
}

const uint8_t* Proto::GetBuffer() const
{
	return m_pBuffer.data();
}

size_t Proto::GetSize() const
{
	return m_pBuffer.size();
}

bool Proto::Unpack(const uint8_t* pbInput, size_t nLength)
{
	if (!pbInput || nLength < sizeof(uint32_t))
		return false;

	m_pBuffer.clear();

	// Get FourCC
	const uint32_t* dwFourCC = reinterpret_cast<const uint32_t*>(pbInput);
	uint32_t dwHeaderSize = sizeof(uint32_t);

	if (*dwFourCC == m_dwFccItemProto)
	{
		dwHeaderSize += sizeof(uint32_t) * 2;

		if (nLength < dwHeaderSize)
			return false;

		m_eType = ProtoType::ItemProto;
		m_dwVersion = *reinterpret_cast<const uint32_t*>(pbInput + sizeof(uint32_t));
		m_dwStride = *reinterpret_cast<const uint32_t*>(pbInput + sizeof(uint32_t) + sizeof(uint32_t));
	}
	else if (*dwFourCC == m_dwFccItemProtoOld)
	{
		m_eType = ProtoType::ItemProto_Old;
	}
	else if (*dwFourCC == m_dwFccMobProto)
	{
		m_eType = ProtoType::MobProto;
	}
	else
		return false; // Unsupported FourCC
	
	if (nLength < (dwHeaderSize + sizeof(uint32_t) + sizeof(uint32_t)))
		return false;

	m_dwElements = *reinterpret_cast<const uint32_t*>(pbInput + dwHeaderSize);
	m_dwCryptedObjectSize = *reinterpret_cast<const uint32_t*>(pbInput + dwHeaderSize + sizeof(uint32_t));
	dwHeaderSize += sizeof(uint32_t) * 2;

	// Get general proto information
	if (nLength < (m_dwCryptedObjectSize + dwHeaderSize))
		return false;

	m_dwCryptedObjectFourCC = *reinterpret_cast<const uint32_t*>(pbInput + dwHeaderSize);

	m_pBuffer.reserve(m_dwCryptedObjectSize);
	m_pBuffer.resize(m_dwCryptedObjectSize);
	memcpy_s(m_pBuffer.data(), m_pBuffer.size(), pbInput + dwHeaderSize, nLength - dwHeaderSize);

	return true;
}

bool Proto::Create(ProtoType eType, uint32_t dwElements)
{
	if (dwElements < 1)
		return false;

	m_dwElements = dwElements;

	m_pBuffer.clear();

	m_eType = eType;
	return true;
}

bool Proto::Pack(const uint8_t* pCryptBuffer, size_t nLength, ProtoType eType, EncryptType sType)
{
	if (!pCryptBuffer || nLength < 1)
		return false;

	m_eType = eType;
	size_t nHeaderLen = (sizeof(uint32_t) * 3);
	m_dwCryptedObjectFourCC = *reinterpret_cast<const uint32_t*>(pCryptBuffer);

	if (m_eType == ProtoType::ItemProto)
		nHeaderLen += sizeof(uint32_t) * 2;

	// 1. Store Crypted Object
	m_pBuffer.reserve(nHeaderLen + nLength);
	m_pBuffer.resize(nHeaderLen + nLength);

	memcpy_s(m_pBuffer.data() + nHeaderLen, nHeaderLen + nLength, pCryptBuffer, nLength);

	// 2. Copy proto info
	m_dwCryptedObjectSize = static_cast<uint32_t>(nLength);

	switch (m_eType)
	{
	case ProtoType::ItemProto:
		memcpy_s(m_pBuffer.data(), nHeaderLen, &m_dwFccItemProto, sizeof(m_dwFccItemProto));
		break;
	case ProtoType::ItemProto_Old:
		memcpy_s(m_pBuffer.data(), nHeaderLen, &m_dwFccItemProtoOld, sizeof(m_dwFccItemProtoOld));
		break;
	case ProtoType::MobProto:
		memcpy_s(m_pBuffer.data(), nHeaderLen, &m_dwFccMobProto, sizeof(m_dwFccMobProto));
		break;
	default:
		return false;
	}

	size_t offs = sizeof(uint32_t);
	if (m_eType == ProtoType::ItemProto)
	{
		memcpy_s(m_pBuffer.data() + sizeof(uint32_t), nHeaderLen - sizeof(uint32_t), &m_dwVersion, sizeof(m_dwVersion));
		memcpy_s(m_pBuffer.data() + sizeof(uint32_t) + sizeof(uint32_t), nHeaderLen - sizeof(uint32_t) - sizeof(uint32_t), &m_dwStride, sizeof(m_dwStride));
		offs += sizeof(uint32_t) * 2;
	}

	memcpy_s(m_pBuffer.data() + offs, nHeaderLen - offs, &m_dwElements, sizeof(m_dwElements));
	offs += sizeof(uint32_t);
	memcpy_s(m_pBuffer.data() + offs, nHeaderLen - offs, &m_dwCryptedObjectSize, sizeof(m_dwCryptedObjectSize));

	return true;
}
