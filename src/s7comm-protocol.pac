## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

##############################
#         CONSTANTS          #
##############################

enum cotp_codes {
    EXPEDITED_DATA      = 0x10,
    CLTP_USER_DATA      = 0x20,
    EXPEDITED_DATA_ACK  = 0x40,
    REJECT              = 0x50,
    ##! ACK_DATA        = 0x60,
    ACK_DATA            = 0x70,
    DISCONNECT_REQUEST  = 0x80,
    DISCONNECT_CONFIRM  = 0xc0,
    CONNECT_CONFIRM     = 0xd0,
    CONNECT_REQUEST     = 0xe0,
    DATA                = 0xf0
    };

##############################
##        RECORD TYPES       #
##############################
type S7comm_PDU(is_orig: bool) = case is_orig of {
    true  -> request    : S7comm_Request;
    false -> response   : S7comm_Response;
    } &byteorder=littleendian;

##! switch for the request portion
type S7comm_Request = record {
    header: ISO_COTP;
    data: case(header.cotp_type) of {
            CONNECT_REQUEST,
            CONNECT_CONFIRM -> connect      : Connection_Header(header);
            DATA            -> dataInfo     : S7comm_Data;
            default         -> unknown      : bytestring &restofdata;
            };
    } &byteorder=bigendian;

##! switch for the response portion
type S7comm_Response = record {
    header: ISO_COTP;
    data: case(header.cotp_type) of {
            CONNECT_REQUEST,
            CONNECT_CONFIRM -> connect      : Connection_Header(header);
            DATA            -> dataInfo     : S7comm_Data;
            default         -> unknown      : bytestring &restofdata;
            };
    } &byteorder=bigendian;

##! Structure of the iso-cotp, used for iso_cotp.log
type ISO_COTP = record {
    tpkt_version    : uint8;
    tpkt_reserved   : uint8;
    tpkt_length     : uint16;
    cotp_length     : uint8;
    cotp_type       : uint8;
    something       : case cotp_type of { ##! only in DATA messages
                        DATA    -> something_value      : uint8;
                        default -> something_default    : empty;
                        };
    } &byteorder=bigendian;

##! iso-cotp connection info
type Connection_Info = record {
    src_tsap: uint16;
    dst_tsap: uint16;
    tpdu_len: uint8;
    } &byteorder=bigendian;

##! iso-cotp connection header
type Connection_Header(header: ISO_COTP) = record {
    destination_reference   : uint16;
    source_reference        : uint16;
    class_options           : uint8;
    ##! check Param_Info.code to verify order of tpdu_size
    source_tsap             : Param_Info; ##! code 0xc1
    destination_tsap        : Param_Info; ##! code 0xc2
    tpdu_size               : Param_Info; ##! code 0xc0
    } &byteorder=bigendian;

##! iso-cotp connection info
type Param_Info = record {
    code    : uint8;
    len     : uint8;
    value   : bytestring &length=len;
    } &byteorder=bigendian;

##! parse out data to generate s7comm.log and s7data.log
type S7comm_Data = record {
    data : bytestring &restofdata; 
    } &byteorder=bigendian;
