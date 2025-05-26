#include "config.h"
#include "Plugin.h"
#include "Analyzer.h"

#include <zeek/analyzer/Component.h>

using namespace zeek;

namespace zeek::plugin::pres { 

Plugin plugin;

plugin::Configuration Plugin::Configure()
{
	plugin::Configuration config;

	config.name = "OSS::PRES";
	config.description = "";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;

	AddComponent(new analyzer::Component("PRES", PRES_Analyzer::Instantiate));

	return config;
}

} // namespace zeek::plugin::pres
