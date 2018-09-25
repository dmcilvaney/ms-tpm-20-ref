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

#include <varmgmt.h>

//
// Offsets and lengths
//
#define SECUREBOOT_VAR_RESERVED_START   (0)
#define SECUREBOOT_VAR_RESERVED_LEN     (32 * 1024)

#define BOOT_VAR_RESERVED_START         (SECUREBOOT_VAR_RESERVED_START + SECUREBOOT_VAR_RESERVED_LEN)
#define BOOT_VAR_RESERVED_LEN           (8 * 1024)

#define PRIVATE_AUTH_VAR_RESERVED_START (BOOT_VAR_RESERVED_START + BOOT_VAR_RESERVED_LEN)
#define PRIVATE_AUTH_VAR_RESERVED_LEN   (4 * 1024)

#define TOTAL_RESERVED_LEN  (SECUREBOOT_VAR_RESERVED_LEN + BOOT_VAR_RESERVED_LEN + PRIVATE_AUTH_VAR_RESERVED_LEN)
#define GENERAL_VAR_START   (PRIVATE_AUTH_VAR_RESERVED_START + PRIVATE_AUTH_VAR_RESERVED_LEN)
#define GENERAL_VAR_LEN     (NV_AUTHVAR_SIZE - (TOTAL_RESERVED_LEN))

// 
// Auth Var storage layout
//
VTYPE_INFO VarInfo[VTYPE_END] =
{
    {
        L"SecureBootVariables", VTYPE_SECUREBOOT,
        SECUREBOOT_VAR_RESERVED_START, SECUREBOOT_VAR_RESERVED_LEN,
        { 0 }, TRUE,
    },
    {
        L"BootVariables", VTYPE_BOOT,
        BOOT_VAR_RESERVED_START, BOOT_VAR_RESERVED_LEN,
        { 0 }, TRUE,
    },
    {
        L"Runtime Private Authenticated Variables", VTYPE_PVT_AUTHENTICATED,
        PRIVATE_AUTH_VAR_RESERVED_START, PRIVATE_AUTH_VAR_RESERVED_LEN,
        { 0 }, TRUE,
    },
    {
        L"General Space", VTYPE_GENERAL,
        GENERAL_VAR_START, GENERAL_VAR_LEN,
        { 0 }, TRUE,
    },
    {
        L"Volatile Variable", VTYPE_VOLATILE,   // VOLATILE AUTH VAR NOT IMPLEMENTED!
        -1, 0,                                  // VOLATILE AUTH VAR NOT IMPLEMENTED!
        { 0 }, FALSE,                           // VOLATILE AUTH VAR NOT IMPLEMENTED!
    }
};

//
// Offsets for NV vriable storage
//
static UINT32 s_nextFree = 0;
static UINT32 s_nvLimit = 0;

//
// Helper function prototype(s)
//

static
BOOLEAN
CompareEntries(
    PCUNICODE_STRING     Name,      // IN
    PCGUID               Guid,      // IN
    PUEFI_VARIABLE       Var        // IN
);

static
VOID
GetVariableType(
    PCWSTR      VarName,    // IN
    PCGUID      VendorGuid, // IN
    ATTRIBUTES  Attributes, // IN
    PVARTYPE    VarType     // OUT
);

static
BOOLEAN
IsSecureBootVar(
    PCWSTR  VarName,        // IN
    PCGUID  VendorGuid      // IN
);

//
// Auth Var Mgmt Functions
//

VOID
SearchList(
    PCUNICODE_STRING     UnicodeName,   // IN
    PCGUID               VendorGuid,    // IN
    PUEFI_VARIABLE      *Var,           // OUT
    VARTYPE             *VarType        // OUT
)
/*++

    Routine Description:

        Search the global in-memory list to check if Var has already been set (written).
        Var may be volatile or non-volatile.

    Arguments:

        UnicodeName - Name of the variable being searched

        VendorGuid - GUID of the variable

        Var - Pointer to the variable's entry in memory. NULL if not found.

        VarType - Type used to determine variable's info and storage

    Returns:

    None

    --*/
{
    UINT32      i;

    // Validate parameters
    if (!(UnicodeName) || !(VendorGuid) || !(Var) || !(VarType))
    {
        return;
    }

    // Run the list
    for (i = 0; i < ARRAY_SIZE(VarInfo); i++)
    {
        PLIST_ENTRY head = &VarInfo[i].Head;
        PLIST_ENTRY cur = head->Flink;

        while ((cur) && (cur != head))
        {
            if (CompareEntries(UnicodeName, VendorGuid, (PUEFI_VARIABLE)cur))
            {
                *Var = (PUEFI_VARIABLE)cur;
                *VarType = VarInfo[i].Type;
            }

            cur = cur->Flink;
        }
    }

    return;
}

TEE_Result
CreateVariable(
    PCUNICODE_STRING        UnicodeName,
    PCGUID                  VendorGuid,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtAttributes,
    UINT32                  DataSize,
    PBYTE                   Data
)
/*++

    Routine Description:

        Function to create a variable

    Arguments:

        UnicodeName - Name of the variable being created

        VendorGuid - GUID of the variable

        Attibutes - UEFI variable attributes

        DataSize - Size in bytes of Data

        Data - pointer to the data

    Returns:
    
        TEE_Result

--*/
{
    UINT32 totalNv = 0, uStrLen = 0;
    TEE_Result status = TEE_SUCCESS;
    PUEFI_VARIABLE newVar = NULL;
    PUNICODE_STRING newStr = NULL;
    PBYTE newData = NULL;

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        // Validate length
        if (DataSize == 0)
        {
            // TODO: I believe there are circumstances under which it is permitted
            //       to create a var with zero DataSize. But I guess we'll cross 
            //       that bridge when we come to it.
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Attempt allocation for variable
        if (!(newVar = TEE_Malloc(sizeof(UEFI_VARIABLE), TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Attempt allocation for variable name
        if (!(newStr  = TEE_Malloc(UnicodeName->MaximumLength, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            TEE_Free(newVar);
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Attempt allocation for variable data
        if (!(newData = TEE_Malloc(DataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            TEE_Free(newVar);
            TEE_Free(newStr);
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Init volatile variable storage
        memset(newVar, 0, sizeof(UEFI_VARIABLE));

        // Init/copy variable name
        newVar->Name = newStr;
        newVar->NameSize = UnicodeName->MaximumLength;
        memmove(newStr, UnicodeName->Buffer, UnicodeName->MaximumLength);

        // Init/copy variable data
        newVar->Data = newData;
        newVar->Size = DataSize;
        memmove(newData, Data, DataSize);

        // Guid
        newVar->VendorGuid = *VendorGuid;

        // Add it to the list
        InsertTailList(&VarInfo[VTYPE_VOLATILE].Head, &newVar->List);

        // Success
        status = TEE_SUCCESS;
        goto Cleanup;
    }
    else
    {
        // Nope, create new non-volatile variable.

        // Get strlen of unicode name
        uStrLen = UnicodeName->MaximumLength;

        // Total NV requirement to store this var
        totalNv = uStrLen + sizeof(UEFI_VARIABLE) + DataSize;

        // Is there enough space remaining?
        if ((totalNv + s_nextFree) > s_nvLimit)
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Write variable structure
        _plat__NvMemoryWrite(s_nextFree, newVar, sizeof(UEFI_VARIABLE));
        s_nextFree += sizeof(UEFI_VARIABLE);

        // Then name
        _plat__NvMemoryWrite(s_nextFree, newStr, uStrLen);
        s_nextFree += uStrLen;

        // Then data
        _plat__NvMemoryWrite(s_nextFree, newData, DataSize);
        s_nextFree += DataSize;

        // TODO: !@#!@#!@# Now do in-memory thing

    }
Cleanup:
    return TEE_SUCCESS;
}

TEE_Result
RetrieveVariable(
    PUEFI_VARIABLE       Var,           // IN
    VARIABLE_GET_RESULT *ResultBuf,     // OUT
    UINT32               ResultBufLen,  // IN
    UINT32              *BytesWritten   // OUT (optional)
)
/*++

    Routine Description:

        Function for getting (reading) a variable's data.

    Arguments:

        Var - Pointer to the variable's entry in memory.

        ResultBuf - Buffer to hold result (attributes, datasize, and data)

        ResultBufLen - Size of ResultBuffer

        BytesWritten - total bytes copied into (or needed for) ResultBuf

    Returns:

        TEE_Result

--*/
{
    UINT32 size = 0;
    TEE_Result status = TEE_SUCCESS;

    // Detect integer overflow
    if (((UINT32)ResultBuf + ResultBufLen) < (UINT32)ResultBuf)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Calculate size of copy
    // TODO: Guard against overflow on this one too
    if (ResultBufLen < (size = (Var->Size + sizeof(VARIABLE_GET_RESULT))))
    {
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Copy variable data
    ResultBuf->Attributes = Var->Attributes.Flags;
    ResultBuf->DataSize = Var->Size;
    ResultBuf->Size = sizeof(VARIABLE_GET_RESULT);
    memmove(ResultBuf->Data, Var->Data, Var->Size);

Cleanup:
    if (BytesWritten) // or needed..
    {
        *BytesWritten = size;
    }

    return status;
}

TEE_Result
DeleteVariable(
    PUEFI_VARIABLE  Var,
    VARTYPE         VarType,
    ATTRIBUTES      Attributes
)
{
    // TODO:
    //  1. SearchList (find it in storage (maybe NV))
    //  2. If NV then _plat__NvMemoryMove to close the gap
    //  3. Remove from in-memory list
    return TEE_SUCCESS;
}

TEE_Result
AppendVariable(
    PUEFI_VARIABLE          Var,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtAttributes,
    PBYTE                   Data,
    UINT32                  DataSize
)
/*++

    Routine Description:

        Function for appending an existing variable

    Arguments:

        Var - Pointer to the variable's entry in memory.

        Attibutes - UEFI variable attributes

        ExtendedAttributes - Pointer to ExtendedAttributes (auth only)

        Data - Pointer to the data

        DataSize - Size in bytes of Data

    Returns:

        TEE_Result

--*/
{
    PBYTE       dstPtr = NULL;
    PBYTE       oldPtr = NULL;
    UINT32      newSize = 0;
    TEE_Result  status = TEE_SUCCESS;

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        // TODO: CHECK FOR OVERFLOW
        newSize = Var->Size + DataSize;

        // Attempt allocation
        if (!(dstPtr = TEE_Malloc(newSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // First, bring over existing variable data
        memmove(dstPtr, Var->Data, Var->Size);

        // Then copy appended data
        memmove(dstPtr + Var->Size, Data, DataSize);

        // Update the list
        TEE_Free((PVOID)Var->Data);
        Var->Size = newSize;
        Var->Data = dstPtr;

        status = TEE_SUCCESS;
        goto Cleanup;
    }

    // Nope, append to existing non-volatile variable.
    // TODO: Append with NV_LINK

Cleanup:
    return status;
}

TEE_Result
ReplaceVariable(
    PUEFI_VARIABLE          Var,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtendedAttributes,
    PBYTE                   Data,
    UINT32                  DataSize
)
/*++

    Routine Description:

        Function for replacing value of an existing volatile variable

    Arguments:

        Var - Pointer to the variable's entry in memory.

        Attibutes - UEFI variable attributes

        ExtendedAttributes - Pointer to ExtendedAttributes (auth only)

        Data - Pointer to the data

        DataSize - Size in bytes of Data

    Returns:

        TEE_Result

--*/
{
    PBYTE       dstPtr = NULL;
    TEE_Result  status = TEE_SUCCESS;

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        // Yes. Make sure varialbe doesn't indicate APPEND_WRITE.
        if (!(Attributes.AppendWrite))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // We're good, attempt allocation
        if (!(dstPtr = TEE_Malloc(DataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Success, copy new entry.
        memmove(dstPtr, Data, DataSize);

        // Update the list
        TEE_Free((PVOID)Var->Data);
        Var->Data = dstPtr;
        Var->Size = DataSize;

        status = TEE_SUCCESS;
        goto Cleanup;
    }

    // Nope, replace existing non-volatile variable.
    // TODO: If (size <= AllocSize) then just do in place (and maybe size is <)
    //       if (size > AllocSize) then replace data and nv_link the rest
    // TODO: And be careful of replace on linked data

Cleanup:
    return status;
}

VOID
QueryByAttribute(
    ATTRIBUTES  Attributes,             // IN
    PUINT64     MaxVarStorage,          // OUT
    PUINT64     RemainingVarStorage,    // OUT
    PUINT64     MaxVarSize              // OUT
)
/*++

    Routine Description:

        Calculates storage space information for the given attributes

    Arguments:

        Attributes - UEFI variable attributes

        MaxVarStorage - Size of storage for EFI variables associted with specified attributes

        RemainingVarStorage - Storage remaining for EFI variables associted with specified attributes

        MaxVarSize - Maximum size of an individual variable with specified attributes

    Returns:

        VOID

--*/
{   
    VARTYPE   varType;

    // Note that since we are not provided a (name,guid) for a query, we
    // cannot provide information on secureboot variable storage.
    GetVariableType(NULL, NULL, Attributes, &varType);

    // TODO: MAGIC!

    // Fill in output values
    if (MaxVarStorage)
    {
        *MaxVarStorage = 0;
    }

    if (RemainingVarStorage)
    {
        *RemainingVarStorage = 0;
    }

    if (MaxVarSize)
    {
        *MaxVarSize = 0;
    }

    return;
}

//
// Helper function(s)
//

static
BOOLEAN
CompareEntries(
    PCUNICODE_STRING     Name,      // IN
    PCGUID               Guid,      // IN
    PUEFI_VARIABLE       Var        // IN
)
/*++

    Routine Description:

        Routine for comparing two NAME_KEYs

    Arguments:

        Entry0, Entry1 - The two structures to compare

    Returns:

        TRUE if the same, FALSE otherwise

--*/
{    
    BOOLEAN retVal = FALSE;

    // First, matching GUIDS?
    if (memcmp(Guid, &Var->VendorGuid, sizeof(GUID)) == 0)
    {
        // Ok, name strings of the same length?
        if (Name->MaximumLength == Var->NameSize)
        {
            // Yes, do they match? (case sensitive!)
            if (wcscmp(Name->Buffer, Var->Name) == 0)
            {
                // Win.
                retVal = TRUE;
            }
        }
    }

    return retVal;
}

static
VOID
GetVariableType(
    PCWSTR      VarName,        // IN
    PCGUID      VendorGuid,     // IN
    ATTRIBUTES  Attributes,     // IN
    PVARTYPE    VarType         // OUT
)
/*++

    Routine Description:

        Function for determining variable type

    Arguments:

        VarName - Name of the variable being searched

        VendorGuid - GUID of the variable

        Attributes - UEFI attributes of the variable

        VarType - Storage for result

    Returns:

        VOID

--*/
{
    // VarName and VendorGuid may be NULL
    if (IsSecureBootVar(VarName, VendorGuid))
    {
        *VarType = VTYPE_SECUREBOOT;
        return;
    }

    // Runtime Auth?
    if ((Attributes.RuntimeAccess) && (Attributes.TimeBasedAuth))
    {
        *VarType = VTYPE_PVT_AUTHENTICATED;
        return;
    }
    
    // Boot only?
    if ((Attributes.BootService) && !(Attributes.RuntimeAccess))
    {
        *VarType = VTYPE_BOOT;
        return;
    }

    // None of the above
    *VarType = VTYPE_GENERAL;
    return;
}

static
BOOLEAN
IsSecureBootVar(
    PCWSTR  VarName,        // IN
    PCGUID  VendorGuid      // IN
)
/*++

    Routine Description:

        Function for checking if a variable is one of DB, DBX, KEK or PK

    Arguments:

        VariableName - Name of the variable being searched

        VendorGuid - GUID of the variable

    Returns:

        TRUE if secureboot variable, FALSE otherwise

--*/
{
    BOOLEAN retVal = FALSE;

    // Without (name, guid) we don't know one way or the other
    if (!(VarName) || !(VendorGuid))
    {
        retVal = FALSE;
        goto Cleanup;
    }

    // db/dbx
    if (memcmp(VendorGuid, &EfiSecurityDatabaseGUID, sizeof(GUID)) == 0)
    {
        if (!(wcscmp(VarName, EFI_IMAGE_SECURITY_DATABASE)) ||
            !(wcscmp(VarName, EFI_IMAGE_SECURITY_DATABASE1)))
        {
            retVal = TRUE;
            goto Cleanup;
        }
    }

    // KEK/PK
    if (memcmp(VendorGuid, &EfiGlobalDatabaseGUID, sizeof(GUID)) == 0)
    {
        if (!(wcscmp(VarName, EFI_KEK_SECURITY_DATABASE)) ||
            !(wcscmp(VarName, EFI_PLATFORMKEY_VARIABLE)))
        {
            retVal = TRUE;
            goto Cleanup;
        }
    }

    // No match
    retVal = FALSE;

Cleanup:
    return retVal;
}