#include "Plugin.h"

namespace plugin { 
    namespace Zeek_S7COMM {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_S7COMM;

plugin::Configuration Plugin::Configure() {
    AddComponent(new ::analyzer::Component("S7COMM", ::analyzer::s7comm::S7COMM_Analyzer::Instantiate));
    
    plugin::Configuration config;
    config.name = "Zeek::S7COMM";
    config.description = "S7COMM Protocol analyzer";
    return config;
    }
