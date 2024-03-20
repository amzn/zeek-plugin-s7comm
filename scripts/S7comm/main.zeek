##! Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
##! SPDX-License-Identifier: BSD-3-Clause

##! Implements base functionality for S7comm analysis.
##! Generates the iso-cotp.log file, containing some information about the iso-cotp pdu type.
##! Generates the S7comm.log file, containing some information about the S7comm data.

module S7comm;

export {
    redef enum Log::ID += {
        LOG_ISO_COTP,
        LOG_S7COMM,
        };

    type ISO_COTP: record {
        ts      : time &optional &log;      ## Time when the command was sent.
        uid     : string &optional &log;    ## Unique ID for the connection.
        id      : conn_id &optional &log;   ## The connection's 4-tuple of endpoint addresses/ports.

        pdu_type: string &optional &log;    ## COTP message type.
        };
    global log_iso_cotp: event(rec: ISO_COTP);
    global log_policy_iso_cotp: Log::PolicyHook;

    type S7comm: record {
        ts          : time &optional &log;          ## Time when the command was sent.
        uid         : string &optional &log;        ## Unique ID for the connection.
        id          : conn_id &optional &log;       ## The connection's 4-tuple of endpoint addresses/ports.

        rosctr      : string &optional &log;        ## the s7 message type
        parameter   : string_vec &optional &log;    ## contains header[(error)class, (error)code], (function)type, (function)mode, (function)group, sub(function), (error)code
        item_count  : count &optional &log;         ## number of data entries
        data_info   : string_vec &optional &log;    ## contains data of 1st entry
        };
    global log_s7comm: event(rec: S7comm);
    global log_policy: Log::PolicyHook;
    }

redef record connection += {
    iso_cotp    : ISO_COTP &optional;
    s7comm      : S7comm &optional;
    };

const ports = {
    102/tcp
    };
redef likely_server_ports += {
    ports
    };

event zeek_init() &priority=5 {
    Log::create_stream(S7comm::LOG_ISO_COTP,
                [$columns=ISO_COTP,
                $ev=log_iso_cotp,
                $path="iso_cotp",
                $policy=log_policy_iso_cotp]);
    Log::create_stream(S7comm::LOG_S7COMM,
                [$columns=S7comm,
                $ev=log_s7comm,
                $path="s7comm",
                $policy=log_policy]);
    Analyzer::register_for_ports(Analyzer::ANALYZER_S7COMM, ports);
    }

##! pass in data string to get back parsed data
function parse_data(data:string, data_index:count, parse_type:count, item_count:count): string_vec {
    local output: string_vec;
    local output_index: count=0;
    local transport_size: count=0;
    local data_length: count=0;
    local data_block_num: count=0;
    local area: count=0;
    local address: count=0;
    local data_value: string="";
    local repetition_factor: count=0;
    switch(parse_type) {
        case 1:
            ##! variable specification
            data_index += 1;
            ##! length of following address specification
            data_index += 1;
            ##! syntax id
            data_index += 1;
            ##! transport size
            transport_size = bytestring_to_count(data[data_index]);
            data_index += 1;
            ##! data length
            data_length = bytestring_to_count(data[data_index:data_index+2]);
            data_index += 2;
            if (data_length > 0) {
                ##! DB number
                data_block_num = bytestring_to_count(data[data_index:data_index+2]);
                data_index += 2;
                ##! area
                area = bytestring_to_count(data[data_index]);
                data_index += 1;
                ##! address, comprised of byte and bit address
                address = bytestring_to_count("\x00"+data[data_index:data_index+3]);
                ##! wireshark format of (area data_block_num.DBX address transport_size length)
                output[output_index] = fmt("%s %d.DBX %s %s %d",
                                            areas[area],
                                            data_block_num,
                                            fmt("%d.%d", address/8, address%8),
                                            item_transport_sizes[transport_size],
                                            data_length);
                }
            break;
        case 2:
            ##! return code
            data_index += 1;
            ##! transport size
            transport_size = bytestring_to_count(data[data_index]);
            data_index += 1;
            ##! data length
            data_length = bytestring_to_count(data[data_index:data_index+2]);
            data_index += 2;
            if (data_length > 0) {
                ##! based on data type, switch and format using bytestring_to_double/int/count
                switch (transport_size) {
                    case 4: ##! BYTE/WORK/DWORD
                        data_value = fmt("0x%s", bytestring_to_hexstr(data[data_index:data_index+data_length/8]));
                        break;
                    case 5, ##! INTEGER
                         6: ##! DOUBLE_INTEGER
                        data_value = fmt("%d", bytestring_to_count(data[data_index:data_index+data_length/8]));
                        break;
                    case 7: ##! REAL
                        data_value = fmt("%f", bytestring_to_double("\x00\x00\x00\x00"+data[data_index:data_index+4]));
                        break;
                    default: ##! display hex as default
                        data_value = fmt("0x%s", bytestring_to_hexstr(data[data_index:data_index+data_length]));
                        break;
                    }
                ##! fill byte for data_length
                if (data_length == 1) {
                    data_index += 1;
                    }
                }
            ##! custom format
            output[output_index] = fmt("%s %s",
                                        data_transport_sizes[transport_size],
                                        data_value);
            break;
        case 3:
            ##! memory area
            area = bytestring_to_count(data[data_index]);
            data_index += 1;
            ##! repetition factor
            repetition_factor = bytestring_to_count(data[data_index]);
            data_index += 1;
            ##! DB number
            data_block_num = bytestring_to_count(data[data_index:data_index+2]);
            data_index += 2;
            ##! start address
            address = bytestring_to_count(data[data_index:data_index+2]);
            data_index += 2;
            ##! wireshark format of (area data_block_num.DBX address transport_size length)
            output[output_index] = fmt("%s %d.%d %d", vartab_areas[area],
                                    address,
                                    data_block_num,
                                    repetition_factor);
            break;
        }
    return output;
    }

event iso_cotp(c: connection, is_orig: bool,
                pdu_type: count) &priority=5 {
    if(!c?$iso_cotp) {
        c$iso_cotp = [$ts=network_time(), $uid=c$uid, $id=c$id];
        add c$service["iso_cotp"];
        }

    c$iso_cotp$ts = network_time();
    c$iso_cotp$pdu_type = cotp_types[pdu_type];

    Log::write(S7comm::LOG_ISO_COTP, c$iso_cotp);
    }

event s7comm_data(c:connection, is_orig:bool,
                    data:string) {
    if(!c?$s7comm) {
        c$s7comm = [$ts=network_time(), $uid=c$uid, $id=c$id];
        add c$service["s7comm"];
        }

    local data_index: count=0;
    data_index += 1;
    ##! ROSCTR
    local rosctr: count = bytestring_to_count(data[data_index]);
    c$s7comm$rosctr = rosctrs[rosctr];
    data_index += 1;
    ##! redundancy id
    data_index += 2;
    ##! protocol data unit reference
    data_index += 2;
    ##! parameter length
    data_index += 2;
    ##! data length
    data_index += 2;
    local transport_size: count;
    local data_length: count;
    local parameter: string_vec;
    local parameter_index: count=0;
    local data_info: string_vec;
    local data_info_index: count=0;
    local item_count: count=0;
    switch(rosctr) {
        case 0x01, ##! job
             0x03: ##! Ack_Data
            ##! ACK_DATA only
            if (rosctr == 0x03) {
                ##! info from header section
                ##! error class
                parameter[parameter_index] = fmt("class=%s", error_classes[bytestring_to_count(data[data_index])]);
                parameter_index += 1;
                data_index += 1;
                ##! error code
                parameter[parameter_index] = fmt("code=%d", bytestring_to_count(data[data_index]));
                parameter_index += 1;
                data_index += 1;
                }
            ##! function
            local function_type: count = bytestring_to_count(data[data_index]);
            parameter[parameter_index] = fmt("type=%s", functions[function_type]);
            parameter_index += 1;
            data_index += 1;
            switch(function_type) {
                case 0x04: ##! Read Var
                    ##! item count
                    item_count = bytestring_to_count(data[data_index]);
                    c$s7comm$item_count = item_count;
                    data_index += 1;
                    ##! use item_count to get all data instead of 1st entry only?
                    switch(rosctr) {
                        case 0x01: ##! job
                            data_info = parse_data(data, data_index, 1, item_count);
                            break;
                        case 0x03: ##! Ack_Data
                            data_info = parse_data(data, data_index, 2, item_count);
                            break;
                        }
                    break;
                case 0x05: ##! Write Var
                    ##! item count
                    item_count = bytestring_to_count(data[data_index]);
                    c$s7comm$item_count = item_count;
                    data_index += 1;
                    ##! use item_count to get all data instead of 1st entry only?
                    switch(rosctr) {
                        case 0x01: ##! job
                            data_info = parse_data(data, data_index, 1, item_count);
                            break;
                        case 0x03: ##! Ack_Data
                            data_info[0] = return_codes[bytestring_to_count(data[data_index])];
                            break;
                        }
                    break;
                }
            break;
        case 0x07: ##! Userdata
            ##! parameter head
            data_index += 3;
            ##! parameter length
            data_index += 1;
            ##! method: req:0x11, resp:0x12
            data_index += 1;
            ##! function mode/group
            local function_data: count=bytestring_to_count(data[data_index]);
            local mode: count=function_data/16;
            parameter[parameter_index] = fmt("mode=%s", user_data_function_modes[mode]);
            parameter_index += 1;
            local function_group: count=function_data%16;
            parameter[parameter_index] = fmt("group=%s", user_data_function_groups[function_group]);
            parameter_index += 1;
            data_index += 1;
            ##! subfunction
            local subfunction: count=bytestring_to_count(data[data_index]);
            data_index += 1;
            switch (function_group) {
                case 0:
                    break;
                case 1: ##! programmer commands
                    parameter[parameter_index] = fmt("sub=%s", user_data_programmer_subfunctions[subfunction]);
                    parameter_index += 1;
                    break;
                case 2: ##! cyclic data
                    parameter[parameter_index] = fmt("sub=%s", user_data_cyclic_subfunctions[subfunction]);
                    parameter_index += 1;
                    break;
                case 3: ##! block functions
                    parameter[parameter_index] = fmt("sub=%s", user_data_block_subfunctions[subfunction]);
                    parameter_index += 1;
                    break;
                case 4: ##! CPU functions
                    parameter[parameter_index] = fmt("sub=%s", user_data_cpu_subfunctions[subfunction]);
                    parameter_index += 1;
                    break;
                case 5: ##! security
                    parameter[parameter_index] = fmt("sub=%s", user_data_sec_subfunctions[subfunction]);
                    parameter_index += 1;
                    break;
                case 6: ##! PBC send/receive
                    parameter[parameter_index] = fmt("sub=%s", user_data_time_subfunctions[subfunction]);
                    parameter_index += 1;
                    break;
                case 7: ##! time functions
                    parameter[parameter_index] = fmt("sub=%s", user_data_time_subfunctions[subfunction]);
                    parameter_index += 1;
                    break;
                default:
                    parameter[parameter_index] = fmt("sub=(%d)", subfunction);
                    parameter_index += 1;
                    break;
                }
            ##! sequence number
            data_index += 1;
            ##! response mode
            if (mode == 0x00 || mode == 0x08 || function_group == 0x01) {
                ##! data unit reference number
                data_index += 1;
                ##! last data unit
                data_index += 1;
                ##! error code
                parameter[parameter_index] = fmt("code=%s", bytestring_to_count(data[data_index]));
                parameter_index += 1;
                data_index += 2;
                }
            switch (function_group) {
                case 1: ##! programmer commands
                    ##! return code
                    data_index += 1;
                    ##! transport size
                    ##!data_info[data_info_index] = fmt("%s", data_transport_sizes[transport_size]);
                    ##!data_info_index += 1;
                    data_index += 1;
                    ##! data length
                    data_length = bytestring_to_count(data[data_index:data_index+2]);
                    data_index += 2;
                    if (data_length > 0) {
                        ##! type of data
                        local data_type: count=bytestring_to_count(data[data_index:data_index+2]);
                        data_index += 2;
                        ##! byte count of total data
                        data_length = bytestring_to_count(data[data_index:data_index+2]);
                        data_index += 2;
                        ##! vartab info
                        data_index += data_type;
                        ##! item count
                        item_count = bytestring_to_count(data[data_index:data_index+2]);
                        c$s7comm$item_count = item_count;
                        data_index += 2;
                        if (mode == 0x04) {
                            data_info = parse_data(data, data_index, 3, item_count);
                            }
                        else if (mode == 0x00 || mode == 0x08) {
                            data_info = parse_data(data, data_index, 2, item_count);
                            }
                        }
                    break;
                case 2: ##! cyclic data
                    ##!data_index += 2;
                    switch (subfunction) {
                        case 1: ##! memory
                            ##! return code
                            data_index += 1;
                            ##! transport size
                            ##!data_info[data_info_index] = fmt("%s", data_transport_sizes[transport_size]);
                            ##!data_info_index += 1;
                            data_index += 1;
                            ##! data length
                            ##!data_length = bytestring_to_count(data[data_index:data_index+2]);
                            data_index += 2;
                            ##! item count
                            item_count = bytestring_to_count(data[data_index:data_index+2]);
                            c$s7comm$item_count = item_count;
                            data_index += 2;
                            switch (mode) {
                                case 0x04: ##! request
                                    ##! interval timebase
                                    data_index += 1;
                                    ##! interval time
                                    data_index += 1;
                                    data_info = parse_data(data, data_index, 1, item_count);
                                    break;
                                case 0x00,   ##! push
                                    0x08:    ##! response
                                    data_info = parse_data(data, data_index, 2, item_count);
                                    break;
                                }
                            break;
                        case 4: ##! unsubscribe
                            data_info = parse_data(data, data_index, 2, 1);
                            break;
                        }
                    break;
                case 4: ##! CPU functions
                    ##! return code
                    data_index += 1;
                    ##! transport size
                    transport_size = bytestring_to_count(data[data_index]);
                    ##!data_info[data_info_index] = fmt("%s", data_transport_sizes[transport_size]);
                    ##!data_info_index += 1;
                    data_index += 1;
                    ##! data length
                    data_length = bytestring_to_count(data[data_index:data_index+2]);
                    data_index += 2;
                    if (data_length > 0) {
                        switch (subfunction) {
                            case 1: ##! read szl
                                data_info[data_info_index] = fmt("%s id=0x%s index=%s",
                                                                data_transport_sizes[transport_size],
                                                                bytestring_to_hexstr(data[data_index:data_index+2]),
                                                                bytestring_to_hexstr(data[data_index+2:data_index+4]));
                                data_info_index += 1;
                                break;
                            case 2: ##! message service
                                ##! subscribed event
                                data_index += 1;
                                ##! reserved
                                data_index += 1;
                                ##! username
                                break;
                            }
                        }
                    break;
                }
            break;
        }
    c$s7comm$parameter = parameter;
    c$s7comm$data_info = data_info;

    Log::write(LOG_S7COMM, c$s7comm);
    delete c$s7comm;
    }

event connection_state_remove(c: connection) &priority=-5 {
    if(c?$s7comm) {
        delete c$s7comm;
        }
    }
