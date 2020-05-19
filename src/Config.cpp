/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*!
	@file Config.cpp
	Defines a configuration class for LibLyketo
*/
#include <LibLyketo/Config.hpp>
#include "Utility.hpp"

// CryptedObjectConfig
CryptedObjectConfig::CryptedObjectConfig() : m_dwForcedAlgorithm(0)
{
	// Default algorithms
	m_mAlgorithms[Utility::FromByteArray("MCOZ")] = std::make_unique<CompressAlgorithmLzo1x>();
	//m_mAlgorithms[Utility::FromByteArray("MCSP")] = std::make_unique<CompressAlgorithmSnappy>();
}

CryptedObjectConfig::~CryptedObjectConfig()
{
}

void CryptedObjectConfig::AddAlgorithm(uint32_t dwFourcc, ICompressAlgorithm* upcAlgorithm)
{
	m_mAlgorithms[dwFourcc] = std::unique_ptr<ICompressAlgorithm>(upcAlgorithm);
}

void CryptedObjectConfig::ForceAlgorithm(uint32_t dwFourcc)
{
	if (m_mAlgorithms.find(dwFourcc) != m_mAlgorithms.end())
		m_dwForcedAlgorithm = dwFourcc;
}

void CryptedObjectConfig::ChangeAlgorithmCode(uint32_t dwOldFourcc, uint32_t dwNewFourcc)
{
	std::map<uint32_t, std::unique_ptr<ICompressAlgorithm>>::iterator it = m_mAlgorithms.find(dwOldFourcc);
	if (it == m_mAlgorithms.end())
		return;

	m_mAlgorithms.erase(it);

	m_mAlgorithms[dwNewFourcc] = std::unique_ptr<ICompressAlgorithm>(it->second.release());
}

ICompressAlgorithm* CryptedObjectConfig::FindAlgorithm(uint32_t dwFourcc)
{
	auto it = m_mAlgorithms.find(dwFourcc);

	if (it == m_mAlgorithms.end())
		return nullptr;

	return it->second.get();
}

ICompressAlgorithm* CryptedObjectConfig::GetForcedAlgorithmOrDefault(uint32_t& dwFourcc)
{
	auto it = m_mAlgorithms.begin();

	if (m_dwForcedAlgorithm == 0)
	{
		dwFourcc = it->first;
		return it->second.get();
	}

	it = m_mAlgorithms.find(m_dwForcedAlgorithm);
	if (it == m_mAlgorithms.end())
	{
		it = m_mAlgorithms.begin();
		dwFourcc = it->first;
		return it->second.get();
	}

	dwFourcc = it->first;
	return it->second.get();
}
// ------------------------------------------------------------------------------------------------------------------

// ProtoConfig
ProtoConfig::ProtoConfig() : dwItemVersion(1), dwItemFourCC(Utility::FromByteArray("MIPX")), dwItemStride(163), dwItemFourCCOld(Utility::FromByteArray("MIPT")), dwMobFourCC(Utility::FromByteArray("MMPT"))
{
}
// ------------------------------------------------------------------------------------------------------------------

// EterPackConfig
EterPackConfig::EterPackConfig() : dwFourCC(Utility::FromByteArray("EPKD")), dwVersion(2)
{
}
// ------------------------------------------------------------------------------------------------------------------

// Config
Config::Config() : m_upCryptedConfig(new CryptedObjectConfig()), m_sProto()
{
	m_pInstance = this;
}

Config::~Config()
{
	m_pInstance = nullptr;
}

Config* Config::m_pInstance = nullptr;
// ------------------------------------------------------------------------------------------------------------------
