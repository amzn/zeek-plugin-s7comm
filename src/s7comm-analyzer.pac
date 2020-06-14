## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

connection S7COMM_Conn(bro_analyzer: BroAnalyzer) {
    upflow   = S7COMM_Flow(true);
    downflow = S7COMM_Flow(false);
    };

%header{
    #define S7_HEADER           0x32
    //cotp_types
    #define EXPEDITED_DATA      0x10
    #define CLTP_USER_DATA      0x20
    #define EXPEDITED_DATA_ACK  0x40
    #define REJECT              0x50
    // #define ACK_DATA         0x60
    #define ACK_DATA            0x70
    #define DISCONNECT_REQUEST  0x80
    #define DISCONNECT_CONFIRM  0xc0
    #define CONNECT_CONFIRM     0xd0
    #define CONNECT_REQUEST     0xe0
    #define DATA                0xf0

    //rosctrs
    #define ROSCTR_JOB          0x01
    #define ROSCTR_ACK          0x02
    #define ROSCTR_ACK_DATA     0x03
    #define ROSCTR_USER_DATA    0x07
    %}

flow S7COMM_Flow(is_orig: bool) {
    # flowunit = S7comm_PDU(is_orig) withcontext(connection, this);
    datagram = S7comm_PDU(is_orig) withcontext(connection, this);

    function iso_cotp(header: ISO_COTP): bool %{
        if(::iso_cotp) {
            // connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_iso_cotp(connection()->bro_analyzer(),
                            connection()->bro_analyzer()->Conn(),
                            is_orig(),
                            ${header.cotp_type});
            }
        return true;
        %}

    ##! handles s7comm.log and s7data.log
    function s7comm_data(s7comm_data: S7comm_Data): bool %{
        if(::s7comm_data) {
            // check protocol for 0x32 
            if (${s7comm_data.data[0]} != S7_HEADER) {
                return false;
                }
            connection()->bro_analyzer()->ProtocolConfirmation();
            BifEvent::generate_s7comm_data(connection()->bro_analyzer(),
                                            connection()->bro_analyzer()->Conn(),
                                            is_orig(),
                                            bytestring_to_val(${s7comm_data.data}));
            }
        return true;
        %}
    };

refine typeattr ISO_COTP += &let {
    proc: bool = $context.flow.iso_cotp(this);
    };
    
refine typeattr S7comm_Data += &let {
    proc: bool = $context.flow.s7comm_data(this);
    };
