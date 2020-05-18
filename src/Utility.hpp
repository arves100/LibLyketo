#pragma once

#include <stdint.h>
#include <vector>

class Utility
{
public:
	inline static uint32_t FromByteArray(const uint8_t* pbIn)
	{
		return *pbIn | (*(pbIn +1) << 8) | (*(pbIn + 2) << 16) | (*(pbIn + 3) << 24);
	}

	inline static uint32_t FromByteArray(const char* szIn)
	{
		return FromByteArray(reinterpret_cast<const uint8_t*>(szIn));
	}

	inline static void ToByteArray(uint32_t dwValue, uint8_t* pbData)
	{
		pbData[3] = (dwValue>>24) & 0xFF;
		pbData[2] = (dwValue>>16) & 0xFF;
		pbData[1] = (dwValue>>8) & 0xFF;
		pbData[0] = dwValue & 0xFF;
	}

	template <typename T, typename K>
	inline static void AddToVector(T value, std::vector<K>& v)
	{
		for (size_t i = 0; i < sizeof(value); i++)
		{
			v.insert(v.begin(), value & 0xFF);
			value = value >> 8;
		}
	}
};
