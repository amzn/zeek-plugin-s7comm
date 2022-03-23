#include "Plugin.h"
#include "zeek/analyzer/Component.h"

namespace plugin {
    namespace Zeek_S7comm {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_S7comm;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new zeek::analyzer::Component("S7comm", analyzer::s7comm::S7comm_Analyzer::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Zeek::S7comm";
    config.description = "S7 communnication protocol analyzer";
    return config;
    }
