
#ifndef BRO_PLUGIN_BRO_LDAP
#define BRO_PLUGIN_BRO_LDAP

#include <plugin/Plugin.h>

namespace plugin {
namespace Bro_LDAP {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	virtual plugin::Configuration Configure();
};

extern Plugin plugin;

}
}

#endif
