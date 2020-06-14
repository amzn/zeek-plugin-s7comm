%include binpac.pac
%include bro.pac

%extern{
    #include "events.bif.h"
    %}

analyzer S7COMM withcontext {
    connection:     S7COMM_Conn;
    flow:           S7COMM_Flow;
    };

%include s7comm-protocol.pac
%include s7comm-analyzer.pac
