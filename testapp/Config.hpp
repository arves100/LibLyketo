#pragma once

#include <string>

#include <stdint.h>

class Config
{
public:
	Config();

	bool Parse(std::string path);

	static Config* instance() { return m_sConfig; }

public:
	uint32_t m_dwLzo1xFcc, m_dwSnappyFcc;
	uint32_t m_ipVersion, m_ipStride;
	uint32_t m_ipNFcc, m_ipOFcc, m_mpFcc, m_dwEixFcc;
	uint32_t m_epkVersion;
	uint8_t m_epkKeys[16], m_eixKeys[16], m_ipKeys[16], m_mpKeys[16];

private:
	void StringToKey(uint8_t* pOut, std::string in);

	static Config* m_sConfig;
};