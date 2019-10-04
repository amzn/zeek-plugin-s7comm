## Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
## SPDX-License-Identifier: BSD-3-Clause

// COTP PDU types
#define CR 0xe0
#define CC 0xd0
#define DR 0x80
#define DC 0xc0
#define DT 0xf0
#define ED 0x10
#define AK 0x60
#define EA 0x20
#define RJ 0x50
#define ERR 0x70

// CR CC class 0 variable parameter types
#define SRC_TSAP 0xc1
#define DST_TSAP 0xc2
#define TPDU_LEN 0xc0

#define ANALYZER_ERROR_UNSUPPORTED_DATA_TYPE  0x4141
#define ANALYZER_ERROR_UNEXPECTED_ITEM_COUNT  0x4242
#define ANALYZER_ERROR_UNEXPECTED_LENGTH      0x4343
#define ANALYZER_ERROR_UNSOPPORTED_ADDRESSING 0x4444
#define S7COMM_MIN_TELEGRAM_LENGTH            10
/**************************************************************************
 * PDU types
 */
#define S7COMM_ROSCTR_JOB                   0x01
#define S7COMM_ROSCTR_ACK                   0x02
#define S7COMM_ROSCTR_ACK_DATA              0x03
#define S7COMM_ROSCTR_USERDATA              0x07

#define S7COMM_MAX_AGE 3

/**************************************************************************
 * Error classes in header
 */
#define S7COMM_ERRCLS_NONE                  0x00
#define S7COMM_ERRCLS_APPREL                0x81
#define S7COMM_ERRCLS_OBJDEF                0x82
#define S7COMM_ERRCLS_RESSOURCE             0x83
#define S7COMM_ERRCLS_SERVICE               0x84
#define S7COMM_ERRCLS_SUPPLIES              0x85
#define S7COMM_ERRCLS_ACCESS                0x87


/**************************************************************************
 * Error code in parameter part
 */
#define S7COMM_PERRCOD_NO_ERROR                     0x0000
#define S7COMM_PERRCOD_INVALID_BLOCK_TYPE_NUM       0x0110
#define S7COMM_PERRCOD_INVALID_PARAM                0x0112
#define S7COMM_PERRCOD_PG_RESOURCE_ERROR            0x011A
#define S7COMM_PERRCOD_PLC_RESOURCE_ERROR           0x011B
#define S7COMM_PERRCOD_PROTOCOL_ERROR               0x011C
#define S7COMM_PERRCOD_USER_BUFFER_TOO_SHORT        0x011F
#define S7COMM_PERRCOD_REQ_INI_ERR                  0x0141
#define S7COMM_PERRCOD_VERSION_MISMATCH             0x01C0
#define S7COMM_PERRCOD_NOT_IMPLEMENTED              0x01F0
#define S7COMM_PERRCOD_L7_INVALID_CPU_STATE         0x8001
#define S7COMM_PERRCOD_L7_PDU_SIZE_ERR              0x8500
#define S7COMM_PERRCOD_L7_INVALID_SZL_ID            0xD401
#define S7COMM_PERRCOD_L7_INVALID_INDEX             0xD402
#define S7COMM_PERRCOD_L7_DGS_CONN_ALREADY_ANNOU    0xD403
#define S7COMM_PERRCOD_L7_MAX_USER_NB               0xD404
#define S7COMM_PERRCOD_L7_DGS_FKT_PAR_SYNTAX_ERR    0xD405
#define S7COMM_PERRCOD_L7_NO_INFO                   0xD406
#define S7COMM_PERRCOD_L7_PRT_FKT_PAR_SYNTAX_ERR    0xD601
#define S7COMM_PERRCOD_L7_INVALID_VAR_ADDR          0xD801
#define S7COMM_PERRCOD_L7_UNKNOWN_REQ               0xD802
#define S7COMM_PERRCOD_L7_INVALID_REQ_STATUS        0xD803

/**************************************************************************
 * Function codes in parameter part
 */
#define S7COMM_SERV_CPU                     0x00
#define S7COMM_SERV_SETUPCOMM               0xF0
#define S7COMM_SERV_READVAR                 0x04
#define S7COMM_SERV_WRITEVAR                0x05

#define S7COMM_FUNCREQUESTDOWNLOAD          0x1A
#define S7COMM_FUNCDOWNLOADBLOCK            0x1B
#define S7COMM_FUNCDOWNLOADENDED            0x1C
#define S7COMM_FUNCSTARTUPLOAD              0x1D
#define S7COMM_FUNCUPLOAD                   0x1E
#define S7COMM_FUNCENDUPLOAD                0x1F
#define S7COMM_FUNC_PLC_CONTROL             0x28
#define S7COMM_FUNC_PLC_STOP                0x29

/**************************************************************************
 * Area names
 */
#define S7COMM_AREA_SYSINFO                 0x03        /* System info of 200 family */
#define S7COMM_AREA_SYSFLAGS                0x05        /* System flags of 200 family */
#define S7COMM_AREA_ANAIN                   0x06        /* analog inputs of 200 family */
#define S7COMM_AREA_ANAOUT                  0x07        /* analog outputs of 200 family */
#define S7COMM_AREA_P                       0x80        /* direct peripheral access */
#define S7COMM_AREA_INPUTS                  0x81
#define S7COMM_AREA_OUTPUTS                 0x82
#define S7COMM_AREA_FLAGS                   0x83
#define S7COMM_AREA_DB                      0x84        /* data blocks */
#define S7COMM_AREA_DI                      0x85        /* instance data blocks */
#define S7COMM_AREA_LOCAL                   0x86        /* local data (should not be accessible over network) */
#define S7COMM_AREA_V                       0x87        /* previous (Vorgaenger) local data (should not be accessible over network)  */
#define S7COMM_AREA_COUNTER                 28          /* S7 counters */
#define S7COMM_AREA_TIMER                   29          /* S7 timers */
#define S7COMM_AREA_COUNTER200              30          /* IEC counters (200 family) */
#define S7COMM_AREA_TIMER200                31          /* IEC timers (200 family) */

/**************************************************************************
 * Transport sizes in item data
 */
    /* types of 1 byte length */
#define S7COMM_TRANSPORT_SIZE_BIT           1
#define S7COMM_TRANSPORT_SIZE_BYTE          2
#define S7COMM_TRANSPORT_SIZE_CHAR          3
    /* types of 2 bytes length */
#define S7COMM_TRANSPORT_SIZE_WORD          4
#define S7COMM_TRANSPORT_SIZE_INT           5
    /* types of 4 bytes length */
#define S7COMM_TRANSPORT_SIZE_DWORD         6
#define S7COMM_TRANSPORT_SIZE_DINT          7
#define S7COMM_TRANSPORT_SIZE_REAL          8
    /* Special types */
#define S7COMM_TRANSPORT_SIZE_DATE          9
#define S7COMM_TRANSPORT_SIZE_TOD           10
#define S7COMM_TRANSPORT_SIZE_TIME          11
#define S7COMM_TRANSPORT_SIZE_S5TIME        12
#define S7COMM_TRANSPORT_SIZE_DT            15
    /* Timer or counter */
#define S7COMM_TRANSPORT_SIZE_COUNTER       28
#define S7COMM_TRANSPORT_SIZE_TIMER         29
#define S7COMM_TRANSPORT_SIZE_IEC_COUNTER   30
#define S7COMM_TRANSPORT_SIZE_IEC_TIMER     31
#define S7COMM_TRANSPORT_SIZE_HS_COUNTER    32

/**************************************************************************
 * Syntax Ids of variable specification
 */
#define S7COMM_SYNTAXID_S7ANY               0x10        /* Adress data S7-Any pointer-like DB1.DBX10.2 */
#define S7COMM_SYNTAXID_DRIVEESANY          0xa2        /* seen on Drive ES Starter with routing over S7 */
#define S7COMM_SYNTAXID_1200SYM             0xb2        /* Symbolic address mode of S7-1200 */
#define S7COMM_SYNTAXID_DBREAD              0xb0        /* Kind of DB block read, seen only at an S7-400 */

/**************************************************************************
 * Transport sizes in data
 */
#define S7COMM_DATA_TRANSPORT_SIZE_NULL     0
#define S7COMM_DATA_TRANSPORT_SIZE_BBIT     3           /* bit access, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BBYTE    4           /* byte/word/dword acces, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BINT     5           /* integer access, len is in bits */
#define S7COMM_DATA_TRANSPORT_SIZE_BREAL    7           /* real access, len is in bytes */
#define S7COMM_DATA_TRANSPORT_SIZE_BSTR     9           /* octet string, len is in bytes */

/**************************************************************************
 * Returnvalues of an item response
 */

/**************************************************************************
 * Block Types
 */
#define S7COMM_BLOCKTYPE_OB                 '8'
#define S7COMM_BLOCKTYPE_DB                 'A'
#define S7COMM_BLOCKTYPE_SDB                'B'
#define S7COMM_BLOCKTYPE_FC                 'C'
#define S7COMM_BLOCKTYPE_SFC                'D'
#define S7COMM_BLOCKTYPE_FB                 'E'
#define S7COMM_BLOCKTYPE_SFB                'F'


/**************************************************************************
 * Subblk types
 */
#define S7COMM_SUBBLKTYPE_OB                0x08
#define S7COMM_SUBBLKTYPE_DB                0x0a
#define S7COMM_SUBBLKTYPE_SDB               0x0b
#define S7COMM_SUBBLKTYPE_FC                0x0c
#define S7COMM_SUBBLKTYPE_SFC               0x0d
#define S7COMM_SUBBLKTYPE_FB                0x0e
#define S7COMM_SUBBLKTYPE_SFB               0x0f


/**************************************************************************
 * Block security
 */
#define S7COMM_BLOCKSECURITY_OFF            0
#define S7COMM_BLOCKSECURITY_KNOWHOWPROTECT 3

/**************************************************************************
 * Names of types in userdata parameter part
 */

#define S7COMM_UD_TYPE_PUSH 0x00
#define S7COMM_UD_TYPE_REQ 0x04
#define S7COMM_UD_TYPE_RES 0x08


/**************************************************************************
 * Userdata Parameter, last data unit
 */
#define S7COMM_UD_LASTDATAUNIT_YES          0x00
#define S7COMM_UD_LASTDATAUNIT_NO           0x01

/**************************************************************************
 * Names of Function groups in userdata parameter part
 */
#define S7COMM_UD_FUNCGROUP_PROG            0x1
#define S7COMM_UD_FUNCGROUP_CYCLIC          0x2
#define S7COMM_UD_FUNCGROUP_BLOCK           0x3
#define S7COMM_UD_FUNCGROUP_CPU             0x4
#define S7COMM_UD_FUNCGROUP_SEC             0x5                     /* Security funnctions e.g. plc password */
#define S7COMM_UD_FUNCGROUP_TIME            0x7


/**************************************************************************
 * Vartab: Typ of data in data part, first two bytes
 */
#define S7COMM_UD_SUBF_PROG_VARTAB_TYPE_REQ 0x14
#define S7COMM_UD_SUBF_PROG_VARTAB_TYPE_RES 0x04

/**************************************************************************
 * Vartab: area of data request
 *
 * Low       Hi
 * 0=M       1=BYTE
 * 1=E       2=WORD
 * 2=A       3=DWORD
 * 3=PEx
 * 7=DB
 * 54=TIMER
 * 64=COUNTER
 */
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_MB      0x01
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_MW      0x02
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_MD      0x03
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_EB      0x11
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_EW      0x12
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_ED      0x13
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_AB      0x21
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_AW      0x22
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_AD      0x23
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEB     0x31
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_PEW     0x32
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_PED     0x33
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBB     0x71
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBW     0x72
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_DBD     0x73
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_T       0x54
#define S7COMM_UD_SUBF_PROG_VARTAB_AREA_C       0x64


/**************************************************************************
 * Names of userdata subfunctions in group 1 (Programmer commands)
 */
#define S7COMM_UD_SUBF_PROG_REQDIAGDATA1    0x01
#define S7COMM_UD_SUBF_PROG_VARTAB1         0x02
#define S7COMM_UD_SUBF_PROG_ERASE           0x0c
#define S7COMM_UD_SUBF_PROG_READDIAGDATA    0x0e
#define S7COMM_UD_SUBF_PROG_REMOVEDIAGDATA  0x0f
#define S7COMM_UD_SUBF_PROG_FORCE           0x10
#define S7COMM_UD_SUBF_PROG_REQDIAGDATA2    0x13


/**************************************************************************
 * Names of userdata subfunctions in group 2 (cyclic data)
 */
#define S7COMM_UD_SUBF_CYCLIC_MEM           0x01
#define S7COMM_UD_SUBF_CYCLIC_UNSUBSCRIBE   0x04


/**************************************************************************
 * Names of userdata subfunctions in group 3 (Block functions)
 */
#define S7COMM_UD_SUBF_BLOCK_LIST           0x01
#define S7COMM_UD_SUBF_BLOCK_LISTTYPE       0x02
#define S7COMM_UD_SUBF_BLOCK_BLOCKINFO      0x03

/**************************************************************************
 * Names of userdata subfunctions in group 4 (CPU functions)
 */
#define S7COMM_UD_SUBF_CPU_READSZL          0x01
#define S7COMM_UD_SUBF_CPU_MSGS             0x02
#define S7COMM_UD_SUBF_CPU_TRANSSTOP        0x03
#define S7COMM_UD_SUBF_CPU_ALARMIND         0x11
#define S7COMM_UD_SUBF_CPU_ALARMINIT        0x13
#define S7COMM_UD_SUBF_CPU_ALARMACK1        0x0b
#define S7COMM_UD_SUBF_CPU_ALARMACK2        0x0c

/**************************************************************************
 * Names of userdata subfunctions in group 5 (Security?)
 */
#define S7COMM_UD_SUBF_SEC_PASSWD           0x01

/**************************************************************************
 * Names of userdata subfunctions in group 7 (Time functions)
 */
#define S7COMM_UD_SUBF_TIME_READ            0x01
#define S7COMM_UD_SUBF_TIME_SET             0x02
#define S7COMM_UD_SUBF_TIME_READF           0x03
#define S7COMM_UD_SUBF_TIME_SET2            0x04

/**************************************************************************
 * Flags for LID access
 */
#define S7COMM_TIA1200_VAR_ENCAPS_LID       0x2
#define S7COMM_TIA1200_VAR_ENCAPS_IDX       0x3
#define S7COMM_TIA1200_VAR_OBTAIN_LID       0x4
#define S7COMM_TIA1200_VAR_OBTAIN_IDX       0x5
#define S7COMM_TIA1200_VAR_PART_START       0x6
#define S7COMM_TIA1200_VAR_PART_LEN         0x7

/**************************************************************************
 * TIA 1200 Area Names for variable access
 */
#define S7COMM_TIA1200_VAR_ITEM_AREA1_DB    0x8a0e              /* Reading DB, 2 byte DB-Number following */
#define S7COMM_TIA1200_VAR_ITEM_AREA1_IQMCT 0x0000              /* Reading I/Q/M/C/T, 2 Byte detail area following */

#define S7COMM_TIA1200_VAR_ITEM_AREA2_I     0x50
#define S7COMM_TIA1200_VAR_ITEM_AREA2_Q     0x51
#define S7COMM_TIA1200_VAR_ITEM_AREA2_M     0x52
#define S7COMM_TIA1200_VAR_ITEM_AREA2_C     0x53
#define S7COMM_TIA1200_VAR_ITEM_AREA2_T     0x54
