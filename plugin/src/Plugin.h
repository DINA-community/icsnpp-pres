#pragma once

#include <zeek/plugin/Plugin.h>

/* This plugin implements the iso presentation layer (ISO 8327-1 aka X.226)
 * It maps all context ids to the associated oid. This mapping can be accessed
 * using the variable iso_8650_context_identifier of the connection object.
 * The plugin determines the correct analyzer of the application layer using
 * the respective oid.
 * The naming convention for such a analyzer is: 
 *   util::canonify_name("ISO:"+oid)
 * (e.g. util::canonify_name("ISO:1.0.9506.4")
 */

namespace zeek::plugin::pres {

class Plugin : public zeek::plugin::Plugin
{
protected:
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

} // namespace zeek::plugin::pres
