/*!
	@file Proto.hpp
	Defines an Item or Mob Proto format.
*/
#pragma once

#include <stdint.h>

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

	bool Decrypt(const uint8_t* pbInput, size_t nLength, const uint32_t adwKeys[]);
	bool Encrypt(const uint8_t* pbInput, size_t nLength, uint32_t dwElements, const uint32_t adwKeys[], ProtoType eType);

	uint32_t GetVersion() const { return m_dwVersion; }
	uint32_t GetElements() const { return m_dwElements; }
	uint32_t GetStride() const { return m_dwStride; }
	uint32_t GetFourCC() const { return m_dwFourCC; }

	const uint8_t* GetBuffer() { return m_upObject->GetBuffer(); }
	size_t GetSize() { return m_upObject->GetSize(); }
	ProtoType GetType() { return m_eType; }

private:
	uint32_t m_dwFourCC;
	uint32_t m_dwVersion;
	uint32_t m_dwStride;
	uint32_t m_dwElements;

	ProtoType m_eType;
	std::unique_ptr<CryptedObject> m_upObject;

	std::vector<uint8_t> m_vBuffer;
};
