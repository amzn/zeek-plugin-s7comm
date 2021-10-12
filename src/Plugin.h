#ifndef ZEEK_PLUGIN_ZEEK_S7COMM
#define ZEEK_PLUGIN_ZEEK_S7COMM

#include <zeek/plugin/Plugin.h>
#include "S7comm.h"

namespace plugin {
    namespace Zeek_S7comm {
        class Plugin : public zeek::plugin::Plugin {
            protected:
                // Overridden from plugin::Plugin.
                virtual zeek::plugin::Configuration Configure();
            };

        extern Plugin plugin;
        }
    }

#endif
