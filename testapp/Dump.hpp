#pragma once

#include <string>

namespace Dump
{
	void EterPack(const std::string& in, const std::string& out);
	void CryptedObject(const std::string& in, const std::string& out);
	void ItemProto(const std::string& in, const std::string& out);
	void MobProto(const std::string& in, const std::string& out);
}
