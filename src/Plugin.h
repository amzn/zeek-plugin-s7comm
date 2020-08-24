#ifndef ZEEK_PLUGIN_ZEEK_S7COMM
#define ZEEK_PLUGIN_ZEEK_S7COMM

#include <plugin/Plugin.h>
#include "S7comm.h"

namespace plugin {
    namespace Zeek_S7comm {
        class Plugin : public ::plugin::Plugin {
            protected:
                // Overridden from plugin::Plugin.
                virtual plugin::Configuration Configure();
            };

        extern Plugin plugin;
        }
    }

#endif
