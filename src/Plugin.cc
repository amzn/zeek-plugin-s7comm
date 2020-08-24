#include "Plugin.h"
#include "analyzer/Component.h"

namespace plugin { 
    namespace Zeek_S7comm {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_S7comm;

plugin::Configuration Plugin::Configure() {
    AddComponent(new ::analyzer::Component("S7comm", ::analyzer::s7comm::S7comm_Analyzer::Instantiate));
    
    plugin::Configuration config;
    config.name = "Zeek::S7comm";
    config.description = "S7 communnication protocol analyzer";
    return config;
    }
