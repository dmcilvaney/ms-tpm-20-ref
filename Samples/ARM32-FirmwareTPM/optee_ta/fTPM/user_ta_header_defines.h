/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

/*
 * The name of this file must not be modified
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <fTPM.h>

#define TA_UUID                     TA_FTPM_UUID

#define TA_FLAGS                    (TA_FLAG_SINGLE_INSTANCE | TA_FLAG_EXEC_DDR | TA_FLAG_INSTANCE_KEEP_ALIVE) 
#define TA_STACK_SIZE               (64 * 1024)
#define TA_DATA_SIZE                (32 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
        "fTPM TA" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }

#endif /*USER_TA_HEADER_DEFINES_H*/
