/*  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "ntdefs.h"
#include "uefidefs.h"
#include <Implementation.h> // fTPM defines

// Total allocation of the fTPM TA's storage for Authenticated Variables
//      fTPM TA storage (128K total):
//                        16K   (0x4000  bytes) - TPM NV storage
//                        512   (0x1000   bytes) - fTPM "Admin" state
//          128K - (16K + 512)  (0x1BE00 bytes) - AuthVar storage
#define NV_AUTHVAR_SIZE     (0x20000UL - (0x4000 + 0x1000)) // NV_AUTHVAR_SIZE
#define NV_AUTHVAR_START    (0x5000UL)  // NV_CHIP_MEMORY_SIZE - NV_AUTHVAR_SIZE

typedef union {
    BYTE  Flags;
    struct
    {
        BYTE NonVolatile   : 1,    // EFI_VARIABLE_NON_VOLATILE
             BootService   : 1,    // EFI_VARIABLE_BOOTSERVICE_ACCESS
             RuntimeAccess : 1,    // EFI_VARIABLE_RUNTIME_ACCESS
             HwErrorRec    : 1,    // EFI_VARIABLE_HARDWARE_ERROR_RECORD
             AuthWrite     : 1,    // EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
             TimeBasedAuth : 1,    // EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
             AppendWrite   : 1,    // EFI_VARIABLE_APPEND_WRITE
             unused0       : 1;    // Unused
    };
} ATTRIBUTES, *PATTRIBUTES;

typedef struct _DATA_BLOB {
    UINT32 DataSize;        // Size of data
    BYTE Data[0];           // Data
} DATA_BLOB, *PDATA_BLOB;

// Extended attributes for authenticated variables
typedef struct _EXTENDED_ATTRIBUTES
{
    EFI_TIME EfiTime;       // Timestamp
    DATA_BLOB PublicKey;    // For non-SecureBoot variables
} EXTENDED_ATTRIBUTES, *PEXTENDED_ATTRIBUTES;

// UEFI Variable Structure
typedef struct _UEFI_VARIABLE
{
    LIST_ENTRY List;        // Flink/Blink
    GUID VendorGuid;        // Associated GUID
    ATTRIBUTES Attributes;  // UEFI variable attributes
    USHORT NameSize;        // Length of var name
    INT_PTR Name;           // Offset/ptr to var name
    UINT32 AllocSize;       // Total size of this var entry
    UINT32 ExtAttribSize;   // Size of extended attributes (auth only)
    INT_PTR ExtAttrib;      // Offset/ptr to extended attributes (auth only)
    UINT32 DataSize;        // Size of var data
    INT_PTR Data;           // Offset/ptr to var data
    INT_PTR Start;          // NV Only: Starting offset for variable in NV
    INT_PTR End;            // NV Only: Ending offset for variable in NV
    INT_PTR Next;           // NV Only: Offset to appended data (or zero)
} UEFI_VARIABLE, *PUEFI_VARIABLE;
typedef CONST UEFI_VARIABLE *PCUEFI_VARIABLE;

// AuthVar state in fTPM Admin data
typedef struct _AUTHVAR_STATE
{
    UINT32  NvEnd;          // Offset to first byte beyond AuthVar NV data
} NV_AUTHVAR_STATE, *PNV_AUTHVAR_STATE;

//// UEFI Variable Structure
//typedef struct _UEFI_VARIABLE
//{
//    LIST_ENTRY List;        // Flink/Blink
//    GUID VendorGuid;        // Associated GUID
//    ATTRIBUTES Attributes;  // UEFI variable attributes
//    USHORT NameSize;        // Length of var name
//    PWSTR Name;             // Offset/ptr to var name
//    UINT32 Size;            // Size of variable data
//    UINT32 AllocSize;       // NV Only: Allocated (i.e., maximum) size
//    UINT32 StartOffset;     // NV Only: Starting offset in NV
//    UINT32 Next;            // NV Only: Offset to NV_LINK'ed data (or zero)
//    PBYTE Data;             // Pointer to in-memory variable data
//    PEXTENDED_ATTRIBUTES ExtendedAttributes;    // Auth only
//} UEFI_VARIABLE, *PUEFI_VARIABLE;
//typedef CONST UEFI_VARIABLE *PCUEFI_VARIABLE;


// Struct for Get and GetNextVariable operations (REVISIT: Member ordering)
typedef struct _VARIABLE_GET_PARAM
{
    UINT32 Size;            // Request size
    UINT16 NameSize;        // Size of variable name
    GUID VendorGuid;        // Associated GUID
    WCHAR Name[1];          // Variable name
} VARIABLE_GET_PARAM, VARIABLE_GET_NEXT_PARAM, VARIABLE_GET_NEXT_RESULT, *PVARIABLE_GET_PARAM;
typedef struct _VARIABLE_GET_PARAM *PVARIABLE_GET_NEXT_PARAM, *PVARIABLE_GET_NEXT_RESULT;


// Result struct for Get operation
typedef struct _VARIABLE_GET_RESULT
{
    UINT32 Size;            // Size of response (total)
    UINT32 Attributes;      // Associated UEFI variable attributes
    UINT32 DataSize;        // Size of variable data
    BYTE Data[1];           // Variable data
} VARIABLE_GET_RESULT, *PVARIABLE_GET_RESULT;


// Parameter Struct for Set Operations. No data returned in result!
typedef struct _VARIABLE_SET_PARAM
{
    UINT32 Size;            // Size of set param (total)           
    UINT16 NameSize;        // Length of var name
    GUID VendorGuid;        // Associated GUID
    ATTRIBUTES Attributes;  // UEFI variable attributes
    UINT32 DataSize;        // Size of variable data
    UINT32 OffsetName;      // Offset to variable name
    UINT32 OffsetData;      // Offset to variable data
    BYTE Payload[1];        // Start of "payload", indexed by offsets
} VARIABLE_SET_PARAM, *PVARIABLE_SET_PARAM; // Immediately followed by name and data


// Parameter struct for Query
typedef struct _VARIABLE_QUERY_PARAM
{
    UINT32 Size;            // Size of query param
    ATTRIBUTES Attributes;  // Associated UEFI variable attributes
} VARIABLE_QUERY_PARAM, *PVARIABLE_QUERY_PARAM;


// Query Response
typedef struct _VARIABLE_QUERY_RESULT
{
    UINT32 Size;
    UINT64 MaximumVariableStorageSize;
    UINT64 RemainingVariableStorageSize;
    UINT64 MaximumVariableSize;
} VARIABLE_QUERY_RESULT, *PVARIABLE_QUERY_RESULT;


// UEFI variable types
typedef enum _VARTYPE
{
    // Secureboot non-volatile variables : DB/DBX/KEK/PK
    VTYPE_SECUREBOOT = 0,

    // Non-volatile Variables which have boot access
    VTYPE_BOOT,

    // Runtime non-volatile variables which are authenticated on set
    VTYPE_PVT_AUTHENTICATED,

    // All other non-volatile variables which don't fit above definitions
    VTYPE_GENERAL,

    // Volatile variables
    VTYPE_VOLATILE,

    // Signify end of enum. Equals number of types.
    VTYPE_END,
} VARTYPE, *PVARTYPE;


// Structure for variable storage
typedef struct _VSVARTYPEINFO
{
    PCWSTR Name;                    // Var category name (storage area)
    CONST VARTYPE Type;             // Var type for this space
    CONST UINT32 StartByte;         // Start of reservation (TODO: REMOVE)
    UINT32 RemainingBytes;          // Available storage
    LIST_ENTRY Head;                // Pointer to top of category list
    CONST BOOLEAN IsNonVolatile;    // Vars in this section are [non-]volatile
} VTYPE_INFO;

// Secureboot authenticated variable defs
typedef enum _SECUREBOOT_VARIABLE
{
    SecureBootVariablePK = 0,
    SecureBootVariableKEK,
    SecureBootVariableDB,
    SecureBootVariableDBX,
    SecureBootVariableEnd,
} SECUREBOOT_VARIABLE, *PSECUREBOOT_VARIABLE;

typedef struct _SECUREBOOT_VARIABLE_INFO
{
    SECUREBOOT_VARIABLE Id;
    UNICODE_STRING UnicodeName;
    GUID VendorGuid;
} SECUREBOOT_VARIABLE_INFO;

//
// Externs
//
extern bool fTPMIsRuntime;                  // ExitBootServices() called?
extern bool SecureBootInUserMode;           // Track PK set/unset 
extern const GUID EfiGlobalDatabaseGUID;    // EFI GUID
extern const GUID EfiSecurityDatabaseGUID;  // EFI GUID
extern VTYPE_INFO VarInfo[VTYPE_END];       // Variable storage

//
// Variable operation prototypes
//
TEE_Result
GetVariable(
    UINT32               GetParamSize,
    VARIABLE_GET_PARAM  *GetParam,
    UINT32              *GetReultSize,
    VARIABLE_GET_RESULT *GetResult
);

TEE_Result
GetNextVariableName(
    UINT32                      GetNextParamSize,
    VARIABLE_GET_NEXT_PARAM    *GetNextParam,
    UINT32                     *GetNextResultSize,
    VARIABLE_GET_NEXT_RESULT   *GetNextResult
);

TEE_Result
SetVariable(
    UINT32               SetParamSize,
    VARIABLE_SET_PARAM  *SetParam
);

TEE_Result
QueryVariableInfo(
    UINT32                   QueryParamSize,
    VARIABLE_QUERY_PARAM    *QueryParam,
    UINT32                  *QueryResultSize,
    VARIABLE_QUERY_RESULT   *QueryResult
);