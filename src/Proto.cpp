/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file Proto.cpp
	Defines an Item or Mob Proto format.
*/
#include <LibLyketo/Proto.hpp>
#include <LibLyketo/Config.hpp>
#include "Utility.hpp"

Proto::Proto() : m_dwFourCC(0), m_dwVersion(0), m_dwStride(0), m_dwElements(0), m_eType(ProtoType::MobProto), m_upObject(new CryptedObject())
{

}

Proto::~Proto()
{
}

bool Proto::Decrypt(const uint8_t* pbInput, size_t nLength, const uint32_t adwKeys[])
{
	if (!pbInput || !adwKeys || nLength < 4)
		return false;

	// Get FourCC
	m_dwFourCC = Utility::FromByteArray(pbInput);

	auto sProto = Config::Instance()->Proto();
	size_t nOffset = 4;
	size_t nHeaderSize = 12;

	if (nLength < nHeaderSize)
		return false;

	if (m_dwFourCC == sProto.dwItemFourCC)
	{
		nHeaderSize += 8;

		if (nLength < nHeaderSize)
			return false;

		m_eType = ProtoType::ItemProto;

		// Get MIPX exclusive information
		m_dwVersion = Utility::FromByteArray(pbInput + nOffset);
		m_dwStride = Utility::FromByteArray(pbInput + nOffset + 4);
		nOffset += 8;
	}
	else if (m_dwFourCC == sProto.dwItemFourCCOld)
		m_eType = ProtoType::ItemProto_Old;
	else if (m_dwFourCC == sProto.dwMobFourCC)
		m_eType = ProtoType::MobProto;
	else
		return false; // Unsupported FourCC
	
	// Get general proto information
	m_dwElements = Utility::FromByteArray(pbInput + nOffset);
	uint32_t dwCryptedObjectSize = Utility::FromByteArray(pbInput + nOffset + 4);
	nOffset += 8;

	if (nLength < (dwCryptedObjectSize + nHeaderSize))
		return false;

	if (!m_upObject->Decrypt(pbInput + nOffset, nLength - nHeaderSize, adwKeys))
		return false;

	return true;
}

bool Proto::Encrypt(const uint8_t* pbInput, size_t nLength, uint32_t dwElements, const uint32_t adwKeys[], ProtoType eType)
{
	if (!pbInput || nLength < 1 || dwElements < 1 || !adwKeys)
		return false;

	auto sProto = Config::Instance()->Proto();

	if (eType == ProtoType::MobProto)
		m_dwFourCC = sProto.dwMobFourCC;
	else if (eType == ProtoType::ItemProto_Old)
		m_dwFourCC = sProto.dwItemFourCCOld;	
	else if (eType == ProtoType::ItemProto)
	{
		m_dwFourCC = sProto.dwItemFourCC;
		m_dwStride = sProto.dwItemStride;
		m_dwVersion = sProto.dwItemVersion;
	}
	else
		return false;

	m_dwElements = dwElements;
	m_eType = eType;

	if (!m_upObject->Encrypt(pbInput, nLength, adwKeys))
		return false;

	// 1. Store Crypted Object
	m_vBuffer.reserve(m_upObject->GetSize());
	m_vBuffer.resize(m_upObject->GetSize());
	memcpy_s(m_vBuffer.data(), m_vBuffer.size(), m_upObject->GetBuffer(), m_upObject->GetSize());

	// 2. Copy common proto info
	Utility::AddToVector<uint32_t, uint8_t>(static_cast<uint32_t>(m_upObject->GetSize()), m_vBuffer);
	Utility::AddToVector<uint32_t, uint8_t>(m_dwElements, m_vBuffer);

	if (m_eType == ProtoType::ItemProto)
	{
		// Append extra MIPX information
		Utility::AddToVector<uint32_t, uint8_t>(m_dwStride, m_vBuffer);
		Utility::AddToVector<uint32_t, uint8_t>(m_dwVersion, m_vBuffer);
	}

	// 3. Copy FourCC
	Utility::AddToVector<uint32_t, uint8_t>(m_dwFourCC, m_vBuffer);
	return true;
}
