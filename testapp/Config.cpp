#include "Config.hpp"

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <algorithm>

#include <string.h>

using json = nlohmann::json;

#define MAKEFOURCC(ch0, ch1, ch2, ch3) ((uint32_t)(uint8_t)(ch0) | ((uint32_t)(uint8_t)(ch1) << 8) | ((uint32_t)(uint8_t)(ch2) << 16) | ((uint32_t)(uint8_t)(ch3) << 24))

Config::Config() : m_dwLzo1xFcc(MAKEFOURCC('M','C','O','Z')), m_dwSnappyFcc(MAKEFOURCC('M','C','S','P')), m_ipVersion(1), m_ipStride(163), m_ipNFcc(MAKEFOURCC('M','I','P','X')), m_ipOFcc(MAKEFOURCC('M','I','P','T')), m_mpFcc(MAKEFOURCC('M','M','P','T')), m_epkVersion(2), m_dwEixFcc(MAKEFOURCC('E', 'P', 'K', 'D'))
{
	// Default keys
	uint8_t itemproto[] = { 0xA1, 0xA4, 0x02, 0x00, 0xAA, 0x15, 0x54, 0x04, 0xE7, 0x8B, 0x5A, 0x18, 0xAB, 0xD6, 0xAA, 0x01 };
	uint8_t mobproto[] = { 0x46, 0x74, 0x49, 0x00, 0x0B, 0x4A, 0x00, 0x00, 0xB7, 0x6E, 0x08, 0x00, 0x9D, 0x18, 0x68, 0x00 };
	uint8_t epk[] = { 0xB9, 0x9E, 0xB0, 0x02, 0x6F, 0x69, 0x81, 0x05, 0x63, 0x98, 0x9B, 0x28, 0x79, 0x18, 0x1A, 0x00 };
	uint8_t eix[] = { 0x22, 0xB8, 0xB4, 0x04, 0x64, 0xB2, 0x6E, 0x1F, 0xAE, 0xEA, 0x18, 0x00, 0xA6, 0xF6, 0xFB, 0x1C };

	memcpy_s(m_ipKeys, sizeof(m_ipKeys), itemproto, sizeof(itemproto));
	memcpy_s(m_mpKeys, sizeof(m_mpKeys), mobproto, sizeof(mobproto));
	memcpy_s(m_epkKeys, sizeof(m_epkKeys), epk, sizeof(epk));
	memcpy_s(m_eixKeys, sizeof(m_eixKeys), eix, sizeof(eix));

	m_sConfig = this;
}

bool Config::Parse(std::string path)
{
	std::ifstream i(path);

	SPDLOG_TRACE("Open config {0}", path);

	if (!i.is_open())
		return false;

	json j;
	i >> j;
	i.close();

	SPDLOG_TRACE("Config json parse finish");

	if (!j.is_object())
		return false;

	for (auto& e : j.items())
	{
		SPDLOG_TRACE("Config item in root object {0}", e.key());

		if (e.key() == "EterPack")
		{
			for (auto& ee : e.value().items())
			{
				if (ee.key() == "Version")
				{
					if (!ee.value().is_number_unsigned())
					{
						SPDLOG_ERROR("Invalid value for EterPack.Version");
						continue;
					}

					m_epkVersion = ee.value().get<uint32_t>();
					SPDLOG_INFO("Changed EterPack version to {0}", m_epkVersion);
				}
			}
		}
		else if (e.key() == "ItemProto")
		{
			for (auto& ee : e.value().items())
			{
				if (ee.key() == "Version")
				{
					if (!ee.value().is_number_unsigned())
					{
						SPDLOG_ERROR("Invalid value for ItemProto.Version");
						continue;
					}

					m_ipVersion = ee.value().get<uint32_t>();
					SPDLOG_INFO("Changed ItemProto version to {0}", m_ipVersion);
				}
				else if (ee.key() == "Stride")
				{
					if (!ee.value().is_number_unsigned())
					{
						SPDLOG_ERROR("Invalid value for ItemProto.Stride");
						continue;
					}

					m_ipStride = ee.value().get<uint32_t>();
					SPDLOG_INFO("Changed ItemProto stride to {0}", m_ipStride);
				}
			}
		}
		else if (e.key() == "Keys")
		{
			for (auto& ee : e.value().items())
			{
				if (ee.key() == "ItemProto")
				{
					if (!ee.value().is_string())
					{
						SPDLOG_ERROR("Invalid value in Keys.ItemProto");
						continue;
					}

					std::string keys = ee.value().get<std::string>();

					if (keys.length() != 32)
					{
						SPDLOG_ERROR("Invalid key for ItemProto");
						continue;
					}

					std::transform(keys.begin(), keys.end(), keys.begin(), ::toupper);

					StringToKey(m_ipKeys, keys);

					SPDLOG_INFO("Changed ItemProto key to {0}", keys.c_str());
				}
				else if (ee.key() == "MobProto")
				{
					if (!ee.value().is_string())
					{
						SPDLOG_ERROR("Invalid value in Keys.MobProto");
						continue;
					}

					std::string keys = ee.value().get<std::string>();

					if (keys.length() != 32)
					{
						SPDLOG_ERROR("Invalid key for MobProto");
						continue;
					}

					std::transform(keys.begin(), keys.end(), keys.begin(), ::toupper);

					StringToKey(m_mpKeys, keys);

					SPDLOG_INFO("Changed MobProto key to {0}", keys.c_str());
				}
				else if (ee.key() == "EterPackIndex")
				{
					if (!ee.value().is_string())
					{
						SPDLOG_ERROR("Invalid value in Keys.EterPackIndex");
						continue;
					}

					std::string keys = ee.value().get<std::string>();

					if (keys.length() != 32)
					{
						SPDLOG_ERROR("Invalid key for EterPackIndex");
						continue;
					}

					std::transform(keys.begin(), keys.end(), keys.begin(), ::toupper);

					StringToKey(m_eixKeys, keys);

					SPDLOG_INFO("Changed EterPack Index key to {0}", keys.c_str());
				}
				else if (ee.key() == "EterPackContent")
				{
					if (!ee.value().is_string())
					{
						SPDLOG_ERROR("Invalid value in Keys.EterPackIndex");
						continue;
					}

					std::string keys = ee.value().get<std::string>();

					if (keys.length() != 32)
					{
						SPDLOG_ERROR("Invalid key for EterPackContent");
						continue;
					}

					std::transform(keys.begin(), keys.end(), keys.begin(), ::toupper);

					StringToKey(m_epkKeys, keys);

					SPDLOG_INFO("Changed EterPack Content key to {0}", keys.c_str());
				}
			}
		}
		else if (e.key() == "FourCC")
		{
			for (auto& ee : e.value().items())
			{
				if (ee.key() == "MobProto")
				{
					if (!ee.value().is_string())
					{
						SPDLOG_ERROR("Invalid value in FourCC.MobProto");
						continue;
					}

					std::string fcc = ee.value().get<std::string>();

					if (fcc.length() != 4)
					{
						SPDLOG_ERROR("Invalid FourCC for MobProto");
						continue;
					}

					m_mpFcc = MAKEFOURCC(fcc[0], fcc[1], fcc[2], fcc[3]);
					SPDLOG_INFO("Changed MobProto FourCC to {0}", fcc.c_str());
				}
				else if (ee.key() == "ItemProtoOld")
				{
					if (!ee.value().is_string())
					{
						SPDLOG_ERROR("Invalid value in FourCC.ItemProtoOld");
						continue;
					}

					std::string fcc = ee.value().get<std::string>();

					if (fcc.length() != 4)
					{
						SPDLOG_ERROR("Invalid FourCC for ItemProto (Old format)");
						continue;
					}

					m_ipOFcc = MAKEFOURCC(fcc[0], fcc[1], fcc[2], fcc[3]);
					SPDLOG_INFO("Changed ItemProtoOld FourCC to {0}", fcc.c_str());
				}
				else if (ee.key() == "ItemProtoNew")
				{
					if (!ee.value().is_string())
					{
						SPDLOG_ERROR("Invalid value in FourCC.ItemProtoNew");
						continue;
					}

					std::string fcc = ee.value().get<std::string>();

					if (fcc.length() != 4)
					{
						SPDLOG_ERROR("Invalid FourCC for ItemProto (New format)");
						continue;
					}

					m_ipOFcc = MAKEFOURCC(fcc[0], fcc[1], fcc[2], fcc[3]);
					SPDLOG_INFO("Changed ItemProto (New format) FourCC to {0}", fcc.c_str());
				}
				else if (ee.key() == "Snappy")
				{
					if (!ee.value().is_string())
					{
						SPDLOG_ERROR("Invalid value in FourCC.Snappy");
						continue;
					}

					std::string fcc = ee.value().get<std::string>();

					if (fcc.length() != 4)
					{
						SPDLOG_ERROR("Invalid FourCC for Snappy");
						continue;
					}

					m_dwSnappyFcc = MAKEFOURCC(fcc[0], fcc[1], fcc[2], fcc[3]);
					SPDLOG_INFO("Changed Snappy FourCC to {0}", fcc.c_str());
				}
				else if (ee.key() == "Lzo1x")
				{
					if (!ee.value().is_string())
					{
						SPDLOG_ERROR("Invalid value in FourCC.Lzo1x");
						continue;
					}

					std::string fcc = ee.value().get<std::string>();

					if (fcc.length() != 4)
					{
						SPDLOG_ERROR("Invalid FourCC for Lzo1x");
						continue;
					}

					m_dwLzo1xFcc = MAKEFOURCC(fcc[0], fcc[1], fcc[2], fcc[3]);
					SPDLOG_INFO("Changed Lzo1x FourCC to {0}", fcc.c_str());
				}
				else if (ee.key() == "EterPack")
				{
					if (!ee.value().is_string())
					{
						SPDLOG_ERROR("Invalid value in FourCC.EterPack");
						continue;
					}

					std::string fcc = ee.value().get<std::string>();

					if (fcc.length() != 4)
					{
						SPDLOG_ERROR("Invalid EterPack for Lzo1x");
						continue;
					}

					m_dwEixFcc = MAKEFOURCC(fcc[0], fcc[1], fcc[2], fcc[3]);
					SPDLOG_INFO("Changed EterPack FourCC to {0}", fcc.c_str());
				}
			}
		}
	}

	return true;
}

static uint8_t StrCharToNumber(char ch)
{
	switch (ch)
	{
	case 'A':
		return 0xA;
	case 'B':
		return 0xB;
	case 'C':
		return 0xC;
	case 'D':
		return 0xD;
	case 'E':
		return 0xE;
	case 'F':
		return 0xF;
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	default:
		SPDLOG_DEBUG("Invalid character {0} in key conversion", ch);
		break;
	}

	return 0xFF;
}

void Config::StringToKey(uint8_t* pOut, std::string sz)
{
	SPDLOG_DEBUG("Attempt to convert {0} to key", sz);

	uint8_t val = 0;

	for (size_t i = 0, k = 0; i < 32; i += 2, k++)
	{
		val = ((StrCharToNumber(sz[i]) << 4) + StrCharToNumber(sz[i + 1]));
		pOut[k] = val;
	}
}

/*static*/ Config* Config::m_sConfig = nullptr;
