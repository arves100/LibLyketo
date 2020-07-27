#pragma once

#include <LibLyketo/CryptedObject.hpp>
#include <LibLyketo/IFileSystem.hpp>

#include <fstream>

namespace Utility
{
	inline const char* TextFromCOError(CryptedObjectErrors err)
	{
		switch (err)
		{
		case CryptedObjectErrors::NoMemory:
			return "Not neough memory";
		case CryptedObjectErrors::InvalidInput:
			return "Invalid object";
		case CryptedObjectErrors::InvalidAlgorithm:
			return "No algorithm specified";
		case CryptedObjectErrors::InvalidCompressLength:
			return "Compress length is invalid";
		case CryptedObjectErrors::InvalidCryptLength:
			return "Crypted length is invalid";
		case CryptedObjectErrors::InvalidRealLength:
			return "Real length is invalid";
		case CryptedObjectErrors::InvalidCryptAlgorithm:
			return "Algorithm does not support cryptation";
		case CryptedObjectErrors::CompressFail:
			return "Cannot compress or decompress data";
		case CryptedObjectErrors::CryptFail:
			return "Cannot crypt or decrypt data";
		case CryptedObjectErrors::InvalidFourCC:
			return "Invalid FourCC in decryptation";
		default:
			break;
		}

		return "Unknown";
	}

	class DefaultFileSystem : public IFileSystem
	{
	public:
		DefaultFileSystem() : m_write(false)
		{
		
		}

		virtual ~DefaultFileSystem()
		{
		
		}

		bool Open(std::string szFilename, bool write = false)
		{
			m_write = write;
			m_fs.open(szFilename, (write ? std::fstream::app : std::fstream::in) | std::fstream::binary);
			return m_fs.is_open();
		}

		bool Seek(size_t nLength, SeekOffset eOffset) override
		{
			if (m_write)
				m_fs.seekp(nLength, ToStlOffset(eOffset));
			else
				m_fs.seekg(nLength, ToStlOffset(eOffset));

			return true;
		}

		bool Read(uint8_t* pbOut, size_t nLength) override
		{
			m_fs.read(reinterpret_cast<char*>(pbOut), nLength);
			return true;
		}

		bool Write(const uint8_t* pbData, size_t nLength) override
		{
			m_fs.write(reinterpret_cast<const char*>(pbData), nLength);
			return true;
		}

		long Tell() override
		{
			if (m_write)
				return static_cast<long>(m_fs.tellp());

			return  static_cast<long>(m_fs.tellg());
		}

	private:
		std::ios_base::seekdir ToStlOffset(SeekOffset off)
		{
			switch (off)
			{
			case SeekOffset::Start:
				return std::ios_base::beg;
			case SeekOffset::End:
				return std::ios_base::end;
			default:
				break;
			}

			return std::ios_base::cur;
		}

		std::fstream m_fs;
		bool m_write;
	};
}
