#include "Dump.hpp"
#include "Config.hpp"
#include "Log.hpp"
#include "Utility.hpp"

#include <LibLyketo/CryptedObject.hpp>
#include <LibLyketo/DefaultAlgorithms.hpp>
#include <LibLyketo/EterPack.hpp>
#include <LibLyketo/Proto.hpp>

#include <fstream>
#include <memory>

namespace Dump
{
	void CryptedObject(const std::string& in, const std::string& out)
	{
		std::ifstream i(in, std::ifstream::binary);

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

		o << "Dump of CryptedObject: " << in << "\n";

		i.seekg(0, std::ofstream::end);
		auto pos = i.tellg();
		i.seekg(0, std::ofstream::beg);

		std::vector<uint8_t> data;
		data.reserve(sizeof(CryptedObjectHeader));
		data.resize(sizeof(CryptedObjectHeader));

		SPDLOG_DEBUG("Reading input {0} with size {1}", in, sizeof(CryptedObjectHeader));

		i.read(reinterpret_cast<char*>(data.data()), sizeof(CryptedObjectHeader));
		i.close();

		o << "File size: " << pos << "\n";

		CryptedObjectHeader h = *reinterpret_cast<CryptedObjectHeader*>(data.data());

		o << "Dump of CryptedObject:";
		o << "\n\tFourCC: " << h.dwFourCC << " (" << FOURCC1(h.dwFourCC) << FOURCC2(h.dwFourCC) << FOURCC3(h.dwFourCC) << FOURCC4(h.dwFourCC) << ")";
		o << "\n\tAfter compression size: " << h.dwAfterCompressLength;
		o << "\n\tAfter cryptation size: " << h.dwAfterCryptLength;
		o << "\n\tReal size: " << h.dwRealLength << "\n";

		data.clear();

		o << "Dump finished\n";

		o.close();

		SPDLOG_INFO("Completed!");
	}

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

			::CryptedObject obj;

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
			o << "\n\tFourCC: " << h.dwFourCC << " (" << FOURCC1(h.dwFourCC) << FOURCC2(h.dwFourCC) << FOURCC3(h.dwFourCC) << FOURCC4(h.dwFourCC) << ")";
			o << "\n\tKeys: " << obj.GetKeys();
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
		o << "\n\tFourCC: " << h.dwFourCC << " (" << FOURCC1(h.dwFourCC) << FOURCC2(h.dwFourCC) << FOURCC3(h.dwFourCC) << FOURCC4(h.dwFourCC) << ")";
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

	void ItemProto(const std::string& in, const std::string& out)
	{
		std::ifstream i(in, std::ifstream::binary);

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

		o << "Dump of ItemProto: " << in << "\n";

		i.seekg(0, std::ofstream::end);
		auto pos = i.tellg();
		i.seekg(0, std::ofstream::beg);

		std::vector<uint8_t> data;
		data.reserve(pos);
		data.resize(pos);

		SPDLOG_DEBUG("Reading input {0} with size {1}", in, sizeof(CryptedObjectHeader));

		i.read(reinterpret_cast<char*>(data.data()), pos);
		i.close();

		o << "File size: " << pos << "\n";

		auto cfg = Config::instance();

		Proto p;
		p.SetItemFourCC(cfg->m_ipNFcc);
		p.SetItemOldFourCC(cfg->m_ipOFcc);
		p.SetVersion(cfg->m_ipVersion);

		if (!p.Unpack(data.data(), data.size()))
		{
			SPDLOG_CRITICAL("Cannot unpack itemproto");
			return;
		}

		o << "Format type: ";

		switch (p.GetType())
		{
		case ProtoType::ItemProto:
		{
			o << "New";
			o << "\nVersion: " << p.GetVersion();
			o << "\nStride: " << p.GetStride();
			o << "\nElements: " << p.GetElements();
			o << "\nFourCC: " << p.GetItemFourCC() << " (" << FOURCC1(p.GetItemFourCC()) << FOURCC2(p.GetItemFourCC()) << FOURCC3(p.GetItemFourCC()) << FOURCC4(p.GetItemFourCC()) << ")";
			break;
		}
		case ProtoType::ItemProto_Old:
			o << "Old";
			o << "\nElements: " << p.GetElements();
			o << "\nFourCC: " << p.GetItemOldFourCC() << " (" << FOURCC1(p.GetItemOldFourCC()) << FOURCC2(p.GetItemOldFourCC()) << FOURCC3(p.GetItemOldFourCC()) << FOURCC4(p.GetItemOldFourCC()) << ")";
			break;
		default:
			SPDLOG_ERROR("Mobproto type in itemproto");
			break;
		}

		o << "\nCryptedObject size: " << p.GetCryptedObjectSize() << "\n";

		std::shared_ptr<CryptedObjectAlgorithm> algorithm;

		if (p.GetCryptedObjectFourCC() == cfg->m_dwLzo1xFcc)
		{
			algorithm = std::make_shared<DefaultAlgorithmLzo1x>();
			algorithm->ChangeFourCC(cfg->m_dwLzo1xFcc);
		}
		else
		{
			algorithm = std::make_shared<DefaultAlgorithmSnappy>();
			algorithm->ChangeFourCC(cfg->m_dwSnappyFcc);
		}

		::CryptedObject obj;
		obj.SetAlgorithm(algorithm);
		obj.SetKeys(reinterpret_cast<uint32_t*>(cfg->m_ipKeys));

		auto err = obj.Decrypt(p.GetBuffer(), p.GetSize());

		if (err != CryptedObjectErrors::Ok)
		{
			SPDLOG_CRITICAL("Cannot unpack ItemProto. Error {0}", Utility::TextFromCOError(err));
			return;
		}

		auto h = obj.GetHeader();

		o << "Dump of CryptedObject:";
		o << "\n\tFourCC: " << h.dwFourCC << " (" << FOURCC1(h.dwFourCC) << FOURCC2(h.dwFourCC) << FOURCC3(h.dwFourCC) << FOURCC4(h.dwFourCC) << ")";
		o << "\n\tAfter compression size: " << h.dwAfterCompressLength;
		o << "\n\tAfter cryptation size: " << h.dwAfterCryptLength;
		o << "\n\tReal size: " << h.dwRealLength << "\n";

		data.clear();

		o << "Dump finished\n";

		o.close();

		SPDLOG_INFO("Completed!");
	}

	void MobProto(const std::string& in, const std::string& out)
	{
		std::ifstream i(in, std::ifstream::binary);

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

		o << "Dump of MobProto: " << in << "\n";

		i.seekg(0, std::ofstream::end);
		auto pos = i.tellg();
		i.seekg(0, std::ofstream::beg);

		std::vector<uint8_t> data;
		data.reserve(pos);
		data.resize(pos);

		SPDLOG_DEBUG("Reading input {0} with size {1}", in, sizeof(CryptedObjectHeader));

		i.read(reinterpret_cast<char*>(data.data()), pos);
		i.close();

		o << "File size: " << pos << "\n";

		auto cfg = Config::instance();

		Proto p;
		p.SetMobFourCC(cfg->m_mpFcc);

		if (!p.Unpack(data.data(), data.size()))
		{
			SPDLOG_CRITICAL("Cannot unpack itemproto");
			return;
		}

		switch (p.GetType())
		{
		case ProtoType::MobProto:
		{
			o << "Elements: " << p.GetElements();
			o << "\nFourCC: " << p.GetMobFourCC() << " (" << FOURCC1(p.GetMobFourCC()) << FOURCC2(p.GetMobFourCC()) << FOURCC3(p.GetMobFourCC()) << FOURCC4(p.GetMobFourCC()) << ")";
			break;
		}
		default:
			SPDLOG_ERROR("ItemProto type in itemproto");
			break;
		}

		o << "\nCryptedObject size: " << p.GetCryptedObjectSize() << "\n";

		std::shared_ptr<CryptedObjectAlgorithm> algorithm;
		::CryptedObject obj;

		if (p.GetCryptedObjectFourCC() == cfg->m_dwLzo1xFcc)
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
		obj.SetKeys(reinterpret_cast<uint32_t*>(cfg->m_mpKeys));

		auto err = obj.Decrypt(p.GetBuffer(), p.GetSize());

		if (err != CryptedObjectErrors::Ok)
		{
			SPDLOG_CRITICAL("Cannot unpack MobProto. Error {0}", Utility::TextFromCOError(err));
			return;
		}

		auto h = obj.GetHeader();

		o << "Dump of CryptedObject:";
		o << "\n\tFourCC: " << h.dwFourCC << " (" << FOURCC1(h.dwFourCC) << FOURCC2(h.dwFourCC) << FOURCC3(h.dwFourCC) << FOURCC4(h.dwFourCC) << ")";
		o << "\n\tAfter compression size: " << h.dwAfterCompressLength;
		o << "\n\tAfter cryptation size: " << h.dwAfterCryptLength;
		o << "\n\tReal size: " << h.dwRealLength << "\n";

		data.clear();

		o << "Dump finished\n";

		o.close();

		SPDLOG_INFO("Completed!");
	}
}
