#  This Source Code Form is subject to the terms of the Mozilla Public
#   License, v. 2.0. If a copy of the MPL was not distributed with this
#   file, You can obtain one at https://mozilla.org/MPL/2.0/.
#! @file CMakeLists.txt
#  Cmake definition for LibLyketo
cmake_minimum_required(VERSION 3.3)
project(LibLyketo)

add_subdirectory(ext)

option(LIBLYKETO_ENABLE_TESTAPP "Build LyketoCLI Tool" ON)

set(SOURCES
	src/CompressAlgorithms.cpp
	src/Config.cpp
	src/CryptedObject.cpp
	src/Proto.cpp
	src/Utility.hpp
	src/xtea.cpp
	src/xtea.hpp
	src/EterPack.cpp
	src/CompressAlgorithms.hpp
)
	
set(INCLUDES
	include/LibLyketo/Config.hpp
	include/LibLyketo/CryptedObject.hpp
	include/LibLyketo/Proto.hpp
	include/LibLyketo/EterPack.hpp
	include/LibLyketo/Interfaces.hpp
)

set(EXTERNAL
	ext/crc32/Crc32.h
	ext/crc32/Crc32.cpp
)

source_group(LibLyketo FILES ${INCLUDES})
source_group(External FILES ${EXTERNAL})

add_library(${PROJECT_NAME} STATIC ${SOURCES} ${INCLUDES} ${EXTERNAL})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ext)
target_link_libraries(${PROJECT_NAME} PRIVATE lzokay)


if (LIBLYKETO_ENABLE_TESTAPP)
	add_subdirectory(testapp)
endif()
