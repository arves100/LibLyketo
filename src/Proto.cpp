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

ItemProtoHeaderOld::ItemProtoHeaderOld() : dwFourCC(MAKEFOURCC('M', 'I', 'P', 'T')), dwElements(0), dwCryptedObjectSize(0) {}
MobProtoHeader::MobProtoHeader() : dwFourCC(MAKEFOURCC('M', 'M', 'P', 'T')), dwElements(0), dwCryptedObjectSize(0) {}
ItemProtoHeaderNew::ItemProtoHeaderNew() : dwFourCC(MAKEFOURCC('M', 'I', 'P', 'X')), dwVersion(0), dwStride(163), dwElements(0), dwCryptedObjectSize(0) {} // Default 40k stride

Proto::Proto() : m_sItemProtoOld(), m_sMobProto(), m_sItemProtoNew(), m_eType(ProtoType::MobProto), m_upObject(new CryptedObject()), m_pBuffer(nullptr), m_nBufferLen(0)
{

}

Proto::~Proto()
{
	if (m_pBuffer)
		delete[] m_pBuffer;
}

void Proto::SetKeys(const uint32_t* adwKeys)
{
	m_upObject->SetKeys(adwKeys);
}

void Proto::SetAlgorithm(ICryptedObjectAlgorithm* pAlgorithm)
{
	m_upObject->SetAlgorithm(pAlgorithm);
}

const uint8_t* Proto::GetBuffer() const
{
	if (m_pBuffer)
		return m_pBuffer;

	return m_upObject->GetBuffer();
}

size_t Proto::GetSize() const
{
	if (m_pBuffer)
		return m_nBufferLen;

	return m_upObject->GetSize();
}

bool Proto::Unpack(const uint8_t* pbInput, size_t nLength)
{
	if (!pbInput || nLength < sizeof(uint32_t) || !m_upObject->GetAlgorithm())
		return false;

	if (m_pBuffer)
		delete[] m_pBuffer;

	m_pBuffer = nullptr;

	// Get FourCC
	const uint32_t* dwFourCC = reinterpret_cast<const uint32_t*>(pbInput);
	uint32_t dwHeaderSize, dwCryptedObjectSize;

	if (*dwFourCC == m_sItemProtoNew.dwFourCC)
	{
		dwHeaderSize = sizeof(struct ItemProtoHeaderNew);

		if (nLength < dwHeaderSize)
			return false;

		m_eType = ProtoType::ItemProto;
		m_sItemProtoNew = *reinterpret_cast<const struct ItemProtoHeaderNew*>(pbInput);
		dwCryptedObjectSize = m_sItemProtoNew.dwCryptedObjectSize;
	}
	else if (*dwFourCC == m_sItemProtoOld.dwFourCC)
	{
		dwHeaderSize = sizeof(struct ItemProtoHeaderOld);

		if (nLength < dwHeaderSize)
			return false;

		m_eType = ProtoType::ItemProto_Old;
		m_sItemProtoOld = *reinterpret_cast<const struct ItemProtoHeaderOld*>(pbInput);
		dwCryptedObjectSize = m_sItemProtoOld.dwCryptedObjectSize;
	}
	else if (*dwFourCC == m_sMobProto.dwFourCC)
	{
		dwHeaderSize = sizeof(struct MobProtoHeader);

		if (nLength < dwHeaderSize)
			return false;

		m_eType = ProtoType::MobProto;
		m_sMobProto = *reinterpret_cast<const struct MobProtoHeader*>(pbInput);
		dwCryptedObjectSize = m_sMobProto.dwCryptedObjectSize;
	}
	else
		return false; // Unsupported FourCC
	
	// Get general proto information
	if (nLength < (dwCryptedObjectSize + dwHeaderSize))
		return false;

	if (m_upObject->Decrypt(pbInput + dwHeaderSize, nLength - dwHeaderSize) != CryptedObjectErrors::Ok)
		return false;

	return true;
}

bool Proto::Create(ProtoType eType, uint32_t dwElements)
{
	if (dwElements < 1)
		return false;

	switch (eType)
	{
	case ProtoType::ItemProto:
		m_sItemProtoNew.dwElements = dwElements;
		break;
	case ProtoType::MobProto:
		m_sMobProto.dwElements = dwElements;
		break;
	case ProtoType::ItemProto_Old:
		m_sItemProtoOld.dwElements = dwElements;
		break;
	default:
		return false;
	}

	if (m_pBuffer)
		delete[] m_pBuffer;

	m_pBuffer = nullptr;

	m_eType = eType;
	return true;
}

bool Proto::Pack(const uint8_t* pbInput, size_t nLength, bool bEncrypt)
{
	if (!pbInput || nLength < 1 || !m_upObject->GetAlgorithm())
		return false;

	uint32_t dwElements;

	// Setup variables
	switch (m_eType)
	{
	case ProtoType::ItemProto:
		dwElements = m_sItemProtoNew.dwElements;
		m_nBufferLen = m_upObject->GetSize() + sizeof(struct ItemProtoHeaderNew);
		break;
	case ProtoType::MobProto:
		dwElements = m_sMobProto.dwElements;
		m_nBufferLen = m_upObject->GetSize() + sizeof(struct MobProtoHeader);
		break;
	case ProtoType::ItemProto_Old:
		dwElements = m_sItemProtoOld.dwElements;
		m_nBufferLen = m_upObject->GetSize() + sizeof(struct ItemProtoHeaderOld);
		break;
	default:
		return false;
	}

	if (m_upObject->Encrypt(pbInput, nLength, bEncrypt) != CryptedObjectErrors::Ok)
		return false;

	// 1. Store Crypted Object
	m_pBuffer = new uint8_t[m_nBufferLen];
	memcpy_s(m_pBuffer + (m_nBufferLen - m_upObject->GetSize()), m_nBufferLen - m_upObject->GetSize(), m_upObject->GetBuffer(), m_upObject->GetSize());

	// 2. Copy proto info
	switch (m_eType)
	{
	case ProtoType::ItemProto:
		m_sItemProtoNew.dwCryptedObjectSize = static_cast<uint32_t>(m_upObject->GetSize());
		memcpy_s(m_pBuffer, m_nBufferLen, &m_sItemProtoNew, sizeof(m_sItemProtoNew));
		break;
	case ProtoType::ItemProto_Old:
		m_sItemProtoOld.dwCryptedObjectSize = static_cast<uint32_t>(m_upObject->GetSize());
		memcpy_s(m_pBuffer, m_nBufferLen, &m_sItemProtoOld, sizeof(m_sItemProtoOld));
		break;
	case ProtoType::MobProto:
		m_sMobProto.dwCryptedObjectSize = static_cast<uint32_t>(m_upObject->GetSize());
		memcpy_s(m_pBuffer, m_nBufferLen, &m_sMobProto, sizeof(m_sMobProto));
		break;
	default:
		return false;
	}

	return true;
}
