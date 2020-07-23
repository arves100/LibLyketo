#  This Source Code Form is subject to the terms of the Mozilla Public
#   License, v. 2.0. If a copy of the MPL was not distributed with this
#   file, You can obtain one at https://mozilla.org/MPL/2.0/.
#! @file CMakeLists.txt
#  Cmake definition for LibLyketo
cmake_minimum_required(VERSION 3.3)
project(LibLyketo)

option(LIBLYKETO_ENABLE_TESTAPP "Build LyketoCLI Tool" ON)

if (MSVC)
	option(STATIC_CRT "Use Visual C++ static CRT" OFF)

	if(STATIC_CRT)
		set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
		set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
	endif()
endif()

add_subdirectory(ext)
find_package(Snappy CONFIG REQUIRED)



set(SOURCES
	src/DefaultAlgorithms.cpp
	src/CryptedObject.cpp
	src/Proto.cpp
	src/Utility.hpp
	src/xtea.cpp
	src/xtea.hpp
	src/EterPack.cpp
	
)
	
set(INCLUDES
	include/LibLyketo/CryptedObject.hpp
	include/LibLyketo/Proto.hpp
	include/LibLyketo/EterPack.hpp
	include/LibLyketo/IFileSystem.hpp
	include/LibLyketo/ICryptedObjectAlgorithm.hpp
	include/LibLyketo/DefaultAlgorithms.hpp
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
target_link_libraries(${PROJECT_NAME} PRIVATE Snappy::snappy)

if (LIBLYKETO_ENABLE_TESTAPP)
	add_subdirectory(testapp)
endif()
