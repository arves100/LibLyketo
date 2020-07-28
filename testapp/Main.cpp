/*
	Copyright © 2020 Arves100
*/
/*
	LibLyketo Test Application
*/
#include "Config.hpp"
#include "Dump.hpp"
#include "Log.hpp"

#include <cxxopts.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <iostream>

#define DEFAULT_CONFIG_FILE "LyketoCLI.json"

int main(int argc, char* argv[])
{
	cxxopts::Options options("LyketoCli", "LibLyketo CLI test application");

	options.add_options()
		("loglevel", "Changes the logging level", cxxopts::value<std::string>())
		("i,input", "Specify the input file or directory", cxxopts::value<std::string>())
		("o,output", "Specify the output file or directory", cxxopts::value<std::string>())
		("h,help", "Shows the help screen")
		("a,action", "Specify the action to perform", cxxopts::value<std::string>(), "pack,unpack,encrypt,decrypt,dump")
		("t,type", "Specify the input type", cxxopts::value<std::string>(), "item_proto,mob_proto,eterpack")
		("configfile", "Specify a custom config file (default: lyketocli.json)", cxxopts::value<std::string>())
		;

	const auto result = options.parse(argc, argv);

	if (result.count("help") > 0 || (result.count("input") < 1 && result.count("output") < 1 && result.count("type") < 1 && result.count("action") < 1))
	{
		std::cout << options.help() << std::endl;
		return EXIT_SUCCESS;
	}

	// Logger creation
	{
		auto def_logger = spdlog::stdout_color_mt("stdout_logger", spdlog::color_mode::always);

#ifdef _DEBUG
		def_logger->set_pattern("[%H:%M:%S %z] [%^%l%$] [thread %t process %P] %v");
#else
		def_logger->set_pattern("[%H:%M:%S %z] [%^%l%$] %v");
#endif

		spdlog::set_default_logger(def_logger);

#ifdef _DEBUG
		spdlog::set_level(spdlog::level::debug);
#else
		spdlog::set_level(spdlog::level::warn);
#endif

		if (result.count("loglevel") > 0)
		{
			std::string requestedLevel = result["loglevel"].as<std::string>();

			if (requestedLevel == "err")
			{
				spdlog::set_level(spdlog::level::err);
			}
			else if (requestedLevel == "warn")
			{
				spdlog::set_level(spdlog::level::warn);
			}
			else if (requestedLevel == "info")
			{
				spdlog::set_level(spdlog::level::info);
			}
			else if (requestedLevel == "debug")
			{
				spdlog::set_level(spdlog::level::debug);
			}
			else if (requestedLevel == "trace")
			{
				spdlog::set_level(spdlog::level::trace);
			}
			else if (requestedLevel == "off")
			{
				spdlog::set_level(spdlog::level::off);
			}
			else if (requestedLevel == "critical")
			{
				spdlog::set_level(spdlog::level::critical);
			}
			else
			{
				std::cout << "Invalid log level " << requestedLevel << std::endl;
			}
		}
	}

	SPDLOG_INFO("LibLyketo CLI application by Arves100");

	std::string config = DEFAULT_CONFIG_FILE;

	if (result.count("configfile") > 0)
	{
		config = result["configfile"].as<std::string>();
	}

	SPDLOG_DEBUG("Loading config: {0}", config);
	Config cfg;

	if (!cfg.Parse(config))
	{
		SPDLOG_WARN("Cannot parse the config file, default values will be used");
	}

	std::string action, input, output, type;

	if (result.count("action"))
	{
		action = result["action"].as<std::string>();
	}
	
	if(result.count("input"))
	{
		input = result["input"].as<std::string>();
	}

	if (result.count("output"))
	{
		output = result["output"].as<std::string>();
	}

	if (result.count("type"))
	{
		type = result["type"].as<std::string>();
	}

	SPDLOG_DEBUG("Action {0}", action.empty() ? "is empty!" : action);
	SPDLOG_DEBUG("Input {0}", input.empty() ? "is empty!" : input);
	SPDLOG_DEBUG("Output {0}", output.empty() ? "is empty!" : output);
	SPDLOG_DEBUG("Type {0}", type.empty() ? "is empty!" : type);

	if (type != "item_proto" && type != "mob_proto" && type != "eterpack" && type != "cryptobject")
	{
		SPDLOG_CRITICAL("Invalid type argument {0}", type);
		return EXIT_FAILURE;
	}

	if (action != "dump" && action != "encrypt" && action != "decrypt" && action != "unpack" && action != "pack")
	{
		SPDLOG_CRITICAL("Invalid action {0}", action);
		return EXIT_FAILURE;
	}

	if (action == "dump")
	{
		if (type == "eterpack")
			Dump::EterPack(input, output);
		else if (type == "cryptobject")
			Dump::CryptedObject(input, output);
		else if (type == "item_proto")
			Dump::ItemProto(input, output);
		else if (type == "mob_proto")
			Dump::MobProto(input, output);
	}

	return EXIT_SUCCESS;
}
