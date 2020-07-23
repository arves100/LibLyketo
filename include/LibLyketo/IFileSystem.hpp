/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at https://mozilla.org/MPL/2.0/. */
#ifndef IFILESYSTEM_HPP
#define IFILESYSTEM_HPP
#pragma once

#include <stdint.h>

enum class SeekOffset
{
	Start,
	End,
	Current,
};

class IFileSystem
{
public:
	IFileSystem() {}
	virtual ~IFileSystem() {}

	virtual bool Seek(size_t nLength, SeekOffset eOffset) { return false; }
	virtual bool Read(uint8_t* pbOut, size_t nLength) { return false; }
	virtual bool Write(const uint8_t* pbData, size_t nLength) { return false; }
	virtual long Tell() { return 0; }
};

#endif // IFILESYSTEM_HPP
