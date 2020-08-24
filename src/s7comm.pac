%include binpac.pac
%include bro.pac

%extern{
    #include "events.bif.h"
    %}

analyzer S7comm withcontext {
    connection:     S7comm_Conn;
    flow:           S7comm_Flow;
    };

%include s7comm-protocol.pac
%include s7comm-analyzer.pac
