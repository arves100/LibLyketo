#include "Dump.hpp"
#include "Config.hpp"

#include <LibLyketo/CryptedObject.hpp>

#include <fstream>

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include <spdlog/spdlog.h>

namespace Dump
{

	void EterPack(std::string in, std::string out)
	{
		std::ifstream i(in, std::ifstream::binary);

		if (!i.is_open())
		{
			SPDLOG_ERROR("Cannot open file to read {0}", in);
			return;
		}

		std::ofstream o(out, std::ofstream::binary);

		if (!o.is_open())
		{
			SPDLOG_ERROR("Cannot open file to write {0}", out);
			return;
		}

		CryptedObject obj;

		obj.SetKeys()

	}

}
