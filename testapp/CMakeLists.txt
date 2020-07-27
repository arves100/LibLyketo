set(SOURCES
	Main.cpp
	Config.hpp
	Config.cpp
	Dump.hpp
	Dump.cpp
	Utility.hpp
	Log.hpp
)

find_package(spdlog CONFIG REQUIRED)
find_package(cxxopts CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
 
add_executable(LyketoCLI ${SOURCES})
target_link_libraries(LyketoCLI LibLyketo spdlog::spdlog_header_only cxxopts::cxxopts nlohmann_json::nlohmann_json)
