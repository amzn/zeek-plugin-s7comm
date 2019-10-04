cmake_minimum_required(VERSION 2.8)

project(Plugin)

include(ZeekPlugin)

zeek_plugin_begin(Zeek S7comm)
    zeek_plugin_cc(src/S7COMM.cc src/Plugin.cc)
    zeek_plugin_bif(src/events.bif)
    zeek_plugin_pac(src/s7comm.pac src/s7comm-analyzer.pac src/s7comm-protocol.pac)
    zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()
