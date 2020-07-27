#include "Dump.hpp"
#include "Config.hpp"
#include "Log.hpp"
#include "Utility.hpp"

#include <LibLyketo/CryptedObject.hpp>
#include <LibLyketo/DefaultAlgorithms.hpp>
#include <LibLyketo/EterPack.hpp>

#include <fstream>
#include <memory>

namespace Dump
{

	void EterPack(const std::string& in, const std::string& out)
	{
		std::string eix = in + ".eix";

		std::ifstream i(eix, std::ifstream::binary);

		if (!i.is_open())
		{
			SPDLOG_CRITICAL("Cannot open file to read {0}", in);
			return;
		}

		std::ofstream o(out, std::ofstream::binary);

		if (!o.is_open())
		{
			SPDLOG_CRITICAL("Cannot open file to write {0}", out);
			return;
		}

		o << "Dump of EterPack: " << in << "\n";

		i.seekg(0, std::ofstream::end);
		auto pos = i.tellg();
		i.seekg(0, std::ofstream::beg);

		std::vector<uint8_t> data;
		data.reserve(pos);
		data.resize(pos);

		SPDLOG_DEBUG("Reading input {0} with size {1}", eix, pos);

		i.read(reinterpret_cast<char*>(data.data()), pos);
		i.close();

		o << "File size: " << pos << "\n";

		auto cfg = Config::instance();

		uint32_t* magic = reinterpret_cast<uint32_t*>(data.data());

		SPDLOG_DEBUG("Magic is {0}", *magic);

		if (*magic == cfg->m_dwLzo1xFcc || *magic == cfg->m_dwSnappyFcc)
		{
			SPDLOG_DEBUG("EterPack is encrypted, decrypting...");

			CryptedObject obj;

			obj.SetKeys(reinterpret_cast<const uint32_t*>(Config::instance()->m_eixKeys));
			
			std::shared_ptr<CryptedObjectAlgorithm> algorithm;

			if (*magic == cfg->m_dwLzo1xFcc)
			{
				algorithm = std::make_shared<DefaultAlgorithmLzo1x>();
				algorithm->ChangeFourCC(cfg->m_dwLzo1xFcc);
			}
			else
			{
				algorithm = std::make_shared<DefaultAlgorithmSnappy>();
				algorithm->ChangeFourCC(cfg->m_dwSnappyFcc);
			}

			obj.SetAlgorithm(algorithm);

			auto err = obj.Decrypt(data.data(), pos);

			if (err != CryptedObjectErrors::Ok)
			{
				SPDLOG_CRITICAL("Cannot decrypt EIX. Error: {0}", Utility::TextFromCOError(err));
				return;
			}

			auto h = obj.GetHeader();

			o << "Dump of CryptedObject:";
			o << "\n\tFourCC: " << h.dwFourCC << "\n\tKeys: " << obj.GetKeys();
			o << "\n\tDecrypted size (buffer): " << obj.GetSize();
			o << "\n\tAfter compression size: " << h.dwAfterCompressLength;
			o << "\n\tAfter cryptation size: " << h.dwAfterCryptLength;
			o << "\n\tReal size: " << h.dwRealLength << "\n";

			data.clear();
			data.resize(obj.GetSize());
			data.reserve(obj.GetSize());
			memcpy_s(data.data(), data.size(), obj.GetBuffer(), obj.GetSize());

			magic = reinterpret_cast<uint32_t*>(data.data());
		}

		SPDLOG_DEBUG("Magic (2) is {0}", *magic);

		if (*magic != cfg->m_dwEixFcc)
		{
			SPDLOG_CRITICAL("Invalid FourCC in EIX");
			return;
		}

		::EterPack epk;

		epk.SetFourCC(cfg->m_dwEixFcc);
		epk.SetVersion(cfg->m_epkVersion);

		if (!epk.Load(data.data(), data.size(), std::make_shared<Utility::DefaultFileSystem>()))
		{
			SPDLOG_CRITICAL("Cannot load EIX");
			return;
		}

		auto h = epk.GetHeader();

		o << "Dump of EterPack Index:\n";
		o << "\tElements: " << h.dwElements;
		o << "\n\tFourCC: " << h.dwFourCC;
		o << "\n\tVersion: " << h.dwVersion;

		o << "\nDump of elements:\n";

		SPDLOG_INFO("Dumping elements {0}", h.dwElements);

		auto files = epk.GetFiles();

		auto fb = files.begin(), fe = files.end();

		SPDLOG_DEBUG("Files size {0}", files.size());

		for (; fb != fe; fb++)
		{
			auto e = fb->second;
			o << "\tElement: " << e.dwId;
			o << "\n\tFilename: " << e.szFilename;
			o << "\n\tPadding: " << static_cast<uint16_t>(e.bPadding1[0]) << " " << static_cast<uint16_t>(e.bPadding1[1]) << " " << static_cast<uint16_t>(e.bPadding1[2]);
			o << "\n\tFilename CRC32: " << e.dwFilenameCRC32;
			o << "\n\tReal size: " << e.dwRealSize;
			o << "\n\tSize: " << e.dwSize;
			o << "\n\tCRC32: " << e.dwCRC32;
			o << "\n\tPosition: " << e.dwPosition;
			o << "\n\tType: " << static_cast<uint16_t>(e.bType);
			o << "\n\tPadding: " << static_cast<uint16_t>(e.bPadding2[0]) << " " << static_cast<uint16_t>(e.bPadding2[1]) << " " << static_cast<uint16_t>(e.bPadding2[2]);
			o << "\n";
		}

		o << "Dump finished\n";

		o.close();

		SPDLOG_INFO("Completed!");
	}
}
