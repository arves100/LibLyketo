/*!
	@file CryptedObject.cpp
	Implements a Crypted object format, used in raw EterPack and proto files.
*/
#include "CryptedObject.hpp"
#include "Config.hpp"
#include "Utility.hpp"
#include "xtea.hpp"

CryptedObject::CryptedObject() : m_dwFourCC(0), m_dwAfterCryptLength(0), m_dwAfterCompressLength(0), m_dwRealLength(0)
{
}

CryptedObject::~CryptedObject()
{

}

bool CryptedObject::Decrypt(const uint8_t* pbInput, size_t nLength, const uint32_t adwKeys[])
{
	if (!pbInput || !adwKeys || nLength < 20)
		return false;

	m_dwFourCC = Utility::FromByteArray(pbInput);

	 ICompressAlgorithm* algorithm = Config::Instance()->CryptedObject()->FindAlgorithm(m_dwFourCC);

	if (!algorithm)
		return false;

	m_dwAfterCryptLength = Utility::FromByteArray(pbInput + 4);
	m_dwAfterCompressLength = Utility::FromByteArray(pbInput + 8);
	m_dwRealLength = Utility::FromByteArray(pbInput + 12);
	std::vector<uint8_t> data;

	if (m_dwRealLength < 1)
	{
		return false;
	}

	// 1. Decrypt the data
	if (m_dwAfterCryptLength > 0)
	{
		if ((nLength - 20) != m_dwAfterCryptLength)
		{
			return false;
		}
		
		data.resize(m_dwAfterCompressLength + 20); // +19 -.-''
		data.reserve(m_dwAfterCompressLength + 20);

		XTEA::Decrypt(pbInput + 16, data.data(), m_dwAfterCryptLength, adwKeys, 32);

		if (Utility::FromByteArray(data.data()) != m_dwFourCC) // Verify decryptation
		{
			return false;
		}
	}

	// 2. Decompress the data
	if (m_dwAfterCompressLength > 0)
	{
		const uint8_t* inputData;

		if (m_dwAfterCryptLength < 1) // Data is not encrypted
		{
			if ((nLength - 16) != m_dwAfterCompressLength)
				return false;

			data.resize(m_dwAfterCompressLength);
			data.reserve(m_dwAfterCompressLength);
			memcpy_s(data.data(), m_dwAfterCompressLength, pbInput + 16, m_dwAfterCompressLength);

			inputData = data.data();
		}
		else
		{
			inputData = data.data() + 4;
		}

		m_vBuffer.resize(m_dwRealLength);
		m_vBuffer.reserve(m_dwRealLength);

		size_t nRealLength = m_dwRealLength;
		if (!algorithm->Decrypt(inputData, m_vBuffer.data(), m_dwAfterCompressLength, &nRealLength))
		{
			return false;
		}

		if (nRealLength != m_dwRealLength)
		{
			return false;
		}
	}
	else
	{
		if (m_dwAfterCompressLength > 0)
		{
			return true;
		}

		// Data is not compressed at all

		size_t nRealDataLenCalculated = nLength - 16;

		if (nRealDataLenCalculated != m_dwRealLength)
			return false;

		m_vBuffer.resize(nRealDataLenCalculated);
		m_vBuffer.reserve(nRealDataLenCalculated);
		memcpy_s(m_vBuffer.data(), nRealDataLenCalculated, pbInput + 16, nRealDataLenCalculated);
	}

	return true;
}

bool CryptedObject::Encrypt(const uint8_t* pbInput, size_t nLength, const uint32_t adwKeys[])
{
	if (!pbInput || !adwKeys || nLength < 1)
		return false;

	ICompressAlgorithm* algorithm = Config::Instance()->CryptedObject()->GetForcedAlgorithmOrDefault(m_dwFourCC);

	if (!algorithm)
		return false;

	m_dwRealLength = static_cast<uint32_t>(nLength);

	size_t nCompressedSize = algorithm->GetWrostSize(nLength);

	std::vector<uint8_t> data;
	data.reserve(nCompressedSize);
	data.resize(nCompressedSize);

	// 1. Compress the data
	if (!algorithm->Encrypt(pbInput, data.data(), nLength, &nCompressedSize))
	{
		return false;
	}

	m_dwAfterCompressLength = static_cast<uint32_t>(nCompressedSize);

	// 2. Append encrypt FourCC
	data.resize(data.size());
	data.reserve(data.size());

	Utility::AddToVector<uint32_t, uint8_t>(m_dwFourCC, data);

	// 3. Encrypt data
	m_dwAfterCryptLength = m_dwAfterCompressLength + 20;
	m_vBuffer.reserve(m_dwAfterCryptLength);
	m_vBuffer.resize(m_dwAfterCryptLength);

	XTEA::Encrypt(data.data(), m_vBuffer.data(), m_dwAfterCryptLength, adwKeys, 32);

	// 4. Store header
	m_vBuffer.reserve(m_dwAfterCryptLength);
	m_vBuffer.resize(m_dwAfterCryptLength);

	Utility::AddToVector<uint32_t, uint8_t>(m_dwRealLength, data);
	Utility::AddToVector<uint32_t, uint8_t>(m_dwAfterCompressLength, data);
	Utility::AddToVector<uint32_t, uint8_t>(m_dwAfterCryptLength, data);
	Utility::AddToVector<uint32_t, uint8_t>(m_dwFourCC, data);

	return true; 
}
