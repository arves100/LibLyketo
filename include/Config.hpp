/*!
	@file Config.hpp
	Defines a configuration class for LibLyketo
*/
#pragma once

#include "CompressAlgorithms.hpp"
#include "Utility.hpp"

#include <stdint.h>
#include <map>
#include <memory>

class CryptedObjectConfig
{
public:
	CryptedObjectConfig();
	virtual ~CryptedObjectConfig();

	/*!
		Forces an algorithm to be used during cryptation.
		This function should be called before performing any encryptation.

		@param dwFourcc The FourCC of the algoritm to use.
	*/
	void ForceAlgorithm(uint32_t dwFourcc);

	/*!
		Adds an external algorithm.
		This function should be called before any Decrypt and any Encrypt oncurrs.

		@param dwFourcc The FourCC of the new algorithm.
		@param upcAlgorithm A pointer to the new algorithm class.
	*/
	void AddAlgorithm(uint32_t dwFourcc, ICompressAlgorithm* upcAlgorithm);

	/*!
		Changes the FourCC of an algorithm to another.
		This function should be called before any Decrypt and any Encrypt oncurrs.

		@param dwOldFourcc The old FourCC to change.
		@param dwNewFourcc The new FourCC to use.
	*/
	void ChangeAlgorithmCode(uint32_t dwOldFourcc, uint32_t dwNewFourcc);

	/*!
		Finds a compress algorithm from a FourCC.
		
		@param dwFourcc The FourCC to search.
		@return A pointer to the found algorithm or a null pointer if no algorithm exists by such FourCC.
	*/
	ICompressAlgorithm* FindAlgorithm(uint32_t dwFourcc);

	/*!
		Gets the defined forced algorithm or gets the default one in case no forced algorithm is specified.

		@param dwFourcc The variable that will be stored the algorithm's FourCC.
		@return A pointer to the forced algoritithm or a pointer to the default algorithm if the forced one does not exist or it's not specified.
	*/
	ICompressAlgorithm* GetForcedAlgorithmOrDefault(uint32_t& dwFourcc);

private:
	uint32_t m_dwForcedAlgorithm;
	std::map<uint32_t, std::unique_ptr<ICompressAlgorithm>> m_mAlgorithms;
	std::map<uint32_t, uint32_t>  m_mAlgorithmCodes;
};

struct ProtoConfig
{
	uint32_t dwItemVersion;
	uint32_t dwItemFourCC;
	uint32_t dwItemStride;
	uint32_t dwItemFourCCOld;
	uint32_t dwMobFourCC;

	ProtoConfig() : dwItemVersion(1), dwItemFourCC(Utility::FromByteArray("MIPX")), dwItemStride(163), dwItemFourCCOld(Utility::FromByteArray("MIPT")), dwMobFourCC(Utility::FromByteArray("MMPT"))
	{
	}
};

class Config
{
public:
	static Config* Instance() { return m_pInstance; }

	Config();
	virtual ~Config();

	CryptedObjectConfig* CryptedObject() { return m_upCryptedConfig.get(); }

	struct ProtoConfig Proto() { return m_sProto; }

private:
	std::unique_ptr<CryptedObjectConfig> m_upCryptedConfig;
	struct ProtoConfig m_sProto;

	static Config* m_pInstance;
};
