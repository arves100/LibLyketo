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
)
	
set(INCLUDES
	include/LibLyketo/CompressAlgorithms.hpp
	include/LibLyketo/Config.hpp
	include/LibLyketo/CryptedObject.hpp
	include/LibLyketo/Proto.hpp
)

source_group(LibLyketo FILES ${INCLUDES})

add_library(${PROJECT_NAME} STATIC ${SOURCES} ${INCLUDES})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ext)
target_link_libraries(${PROJECT_NAME} PRIVATE lzokay)


if (LIBLYKETO_ENABLE_TESTAPP)
	add_subdirectory(testapp)
endif()
