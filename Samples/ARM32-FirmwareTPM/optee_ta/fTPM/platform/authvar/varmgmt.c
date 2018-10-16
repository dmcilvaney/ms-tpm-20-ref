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
// Offsets and lengths (Note: naturally NV_BLOCK_SIZE aligned!)
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
        L"Volatile Variable", VTYPE_VOLATILE,   // VOLATILE AUTH VARS ARE NOT PERSISTED!
        NULL, 0,                                // VOLATILE AUTH VARS ARE NOT PERSISTED!
        { 0 }, FALSE,                           // VOLATILE AUTH VARS ARE NOT PERSISTED!
    }
};

//
// Offsets/ptrs for NV vriable storage
//
static PBYTE s_NV = NULL;
static UINT32 s_nextFree = NV_AUTHVAR_START;
static const UINT32 s_nvLimit = NV_AUTHVAR_START + NV_AUTHVAR_SIZE;

//
// Handy empty GUID const
//
const GUID GUID_NULL = { 0, 0, 0,{ 0, 0, 0, 0, 0, 0, 0, 0 } };

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
BOOLEAN
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

UINT32
AuthVarInitStorage(
    UINT32 StartingOffset,
    PVOID NvPtr
)
/*++

    Routine Description:

        AuthVar storage initializaion routine

    Arguments:

        StartingOffset - Offset from 0 of first byte of AuthVar NV storage

        NvPtr - Pointer to in-memory NV store for this TA

    Returns:

        0 - Failure

        1 - Success

--*/
{
    NV_AUTHVAR_STATE authVarState;
    PUEFI_VARIABLE pVar;
    PCWSTR name;
    PCGUID guid;
    UINT32 size;
    VARTYPE varType;
    BOOLEAN collapseList;

    // Sanity check on storage offset
    if (StartingOffset != s_nextFree)
    {
        return 0;
    }

    // Init for read
    if ((pVar = (PUEFI_VARIABLE)NvPtr) == NULL)
    {
        return 0;
    }

    // At this point we have read all of NV from storage and we are now
    // in _plat__NVEnable. We now need to traverse our in-memory NV (NvPtr)
    // and add pointers to each UEFI_VARIABLE (that isn't just a container for
    // appended data) to the appropriate in-memory variable list.

    // Also note that the links (flink/blink) in the variable entries in NV
    // may be non-zero. These values are garbage and are ignored. They will
    // be set appropriately when added to the in-memory list(s).

    // Get our Admin state and sanity check ending offset
    DMSG("var");
    _admin__RestoreAuthVarState(&authVarState);
    DMSG("var");
    DMSG("nextFree/NvEnd:%x, size:%x", authVarState.NvEnd, NV_AUTHVAR_SIZE);
    if (!((s_nextFree = authVarState.NvEnd) < NV_AUTHVAR_SIZE))
    {
        DMSG("Sanity check failed");
        return 0;
    }

    if (s_nextFree == StartingOffset) {
        DMSG("First run, we are fine");
        NV_AUTHVAR_STATE authVarState;
		authVarState.NvEnd = s_nextFree;
		_admin__SaveAuthVarState(&authVarState);
        return 1;
    }

    do {
        // Init before gettype
        guid = (PCGUID)&(pVar->VendorGuid);
        name = (PCWSTR)((pVar->Name) + (INT_PTR)pVar);

        // Get type for this var, if not deleted or appended data entry
        if (GetVariableType(name, guid, pVar->Attributes, &varType))
        {
            // Add pointer to this var to appropriate in-memory list
            InsertTailList(&VarInfo[varType].Head, &pVar->List);
        }
        else
        {
            // Appended entry or deleted data? If deleted then close this gap
            if (!memcmp(guid, &GUID_NULL, sizeof(GUID)))
            {
                // Calculate offsets for move
                INT_PTR curOffset = ((INT_PTR)pVar - (INT_PTR)NvPtr);
                INT_PTR srcOffset = curOffset + pVar->AllocSize;
                INT_PTR dstOffset = curOffset;
                UINT32 curLen;

                // Prep for search
                pVar = (PUEFI_VARIABLE)srcOffset;
                curOffset = srcOffset;
                size = 0;

                // Peek ahead and find the next deleted var or end of list
                while ((curOffset < s_nextFree) && memcmp(&(pVar->VendorGuid), &GUID_NULL, sizeof(GUID)))
                {
                    // Accumulate size for move
                    curLen = pVar->AllocSize;
                    size += curLen;

                    // Next iteration
                    curOffset += curLen;
                    pVar = (PUEFI_VARIABLE)((INT_PTR)pVar + curLen);
                }

                // Close the gap.
                _plat__NvMemoryMove(srcOffset, dstOffset, size);

                // Reset pVar for next iteration
                pVar = (PUEFI_VARIABLE)((INT_PTR)NvPtr + dstOffset);
            }
        }

        // Compute pointer to next var
        pVar = (PUEFI_VARIABLE)((INT_PTR)pVar + pVar->AllocSize);
        DMSG("Doing %x is less than %x",((INT_PTR)pVar - (INT_PTR)NvPtr),s_nextFree);
    } while (((INT_PTR)pVar - (INT_PTR)NvPtr) < s_nextFree);

    return 1;
}

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
    UINT32 i;

    DMSG("Search list");

    // Validate parameters
    if (!(UnicodeName) || !(VendorGuid) || !(Var) || !(VarType))
    {
        DMSG("search parameter failed!");
        return;
    }

    *Var = NULL;

    // Run the list(s)
    for (i = 0; i < ARRAY_SIZE(VarInfo); i++)
    {
        PLIST_ENTRY head = &VarInfo[i].Head;
        PLIST_ENTRY cur = head->Flink;
        DMSG("Seraching type %d", i);
        DMSG("Head:%x, cur:%x", head, cur);

        while ((cur) && (cur != head))
        {
            DMSG("Comparing");
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
    PUEFI_VARIABLE newVar = NULL;
    PUNICODE_STRING newStr = NULL;
    PBYTE newData = NULL;
    PEXTENDED_ATTRIBUTES newExt = NULL;
    UINT32 totalNv = 0, uStrLen = 0, extAttribLen = 0;
    VARTYPE varType;
    TEE_Result status = TEE_SUCCESS;

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

        // Guid/Attributes
        newVar->VendorGuid = *VendorGuid;
        newVar->Attributes.Flags = Attributes.Flags;

        // Init/copy variable name
        newVar->NameSize = UnicodeName->MaximumLength;
        newVar->Name = newStr;
        memmove(newStr, UnicodeName->Buffer, UnicodeName->MaximumLength);

        // Init/copy variable data
        newVar->DataSize = DataSize;
        newVar->Data = newData;
        memmove(newData, Data, DataSize);

        // Note the lack of a check against ExtendedAttributes.
        // We do not implement authenticated volatile variables.

        // Add it to the list
        InsertTailList(&VarInfo[VTYPE_VOLATILE].Head, &newVar->List);

        // Success
        status = TEE_SUCCESS;
        goto Cleanup;
    }
    else
    {
        // Nope, create new non-volatile variable.

        // Which list is this variable destined for?
        if (!GetVariableType(UnicodeName->Buffer, VendorGuid, Attributes, &varType))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Get strlen of unicode name
        uStrLen = UnicodeName->MaximumLength;

        // Get size if extended attributes (if provided)
        if (ExtAttributes)
        {
            extAttribLen = sizeof(EXTENDED_ATTRIBUTES) + ExtAttributes->PublicKey.DataSize;
        }
        else
        {
            extAttribLen = 0;
        }

        // Total NV requirement to store this var
        totalNv = sizeof(UEFI_VARIABLE) + uStrLen + DataSize + extAttribLen;

        // Is there enough room on this list and in NV?
        if ( (totalNv > VarInfo[varType].RemainingBytes) ||
            ((totalNv + s_nextFree) > s_nvLimit))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Init pointers to new fields
        newVar = (PUEFI_VARIABLE)s_NV[s_nextFree];
        newStr = (PWSTR)((INT_PTR)newVar + sizeof(UEFI_VARIABLE));
        newExt = (PEXTENDED_ATTRIBUTES)((INT_PTR)newStr + uStrLen);
        newData = (PBYTE)((INT_PTR)newExt + extAttribLen);

        // Init variable structure
        newVar->VendorGuid = *VendorGuid;
        newVar->Attributes.Flags = Attributes.Flags;
        newVar->NameSize = uStrLen;
        newVar->Name = s_nextFree + sizeof(UEFI_VARIABLE);
        
        // Copy name and data
        memmove(newStr, UnicodeName->Buffer, UnicodeName->MaximumLength);

        // Size of var structure before any appended data that may come later
        newVar->AllocSize = totalNv;

        // Extended attributes, if necessary
        if (!extAttribLen)
        {
            // No extended attributes
            newVar->ExtAttribSize = 0;
            newVar->ExtAttrib = 0;
        }
        else
        {
            // Copy extended attributes
            newVar->ExtAttribSize = extAttribLen;
            newVar->ExtAttrib = (INT_PTR)newExt - (INT_PTR)newVar;
            memmove(newExt, ExtAttributes, extAttribLen);
        }

        // Data fields
        newVar->DataSize = DataSize;
        newVar->Data = newData;
        memmove(newData, Data, DataSize);

        // Creating this var we don't yet have appended data
        newVar->Start = s_nextFree;
        newVar->End = s_nextFree + totalNv;
        newVar->Next = 0;

        // We've touched NV so, mark dirty blocks
        _plat__MarkDirtyBlocks(s_nextFree, totalNv);

        // Update offset to next free byte
        s_nextFree += totalNv;

        NV_AUTHVAR_STATE authVarState;
		authVarState.NvEnd = s_nextFree;
		_admin__SaveAuthVarState(&authVarState);

        // Update the in-memory list
        InsertTailList(&VarInfo[varType].Head, &newVar->List);
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
    PBYTE dstPtr;
    INT_PTR nextOffset, limit;
    UINT32 size, length;
    TEE_Result status = TEE_SUCCESS;

    // Detect integer overflow
    if (((UINT32)ResultBuf + ResultBufLen) < (UINT32)ResultBuf)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Sanity check buffer length
    // TODO: Guard against overflow on this one too
    size = Var->DataSize;
    if (ResultBufLen < (size + sizeof(VARIABLE_GET_RESULT)))
    {
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Copy variable data
    ResultBuf->Attributes = Var->Attributes.Flags;
    ResultBuf->DataSize = size;
    ResultBuf->Size = sizeof(VARIABLE_GET_RESULT);

    // Init for copy
    dstPtr = ResultBuf->Data;
    limit = (INT_PTR)dstPtr + size;

    // Do the copy (accross appended data entries if necessary)
    do {
        // Calculate length and copy data
        length = Var->End - Var->Data;
        memmove(dstPtr, (INT_PTR)Var + Var->Data, length);

        // Adjust destination pointer
        dstPtr += length;

        // Pickup offset to next set of appended data (may be zero)
        nextOffset = Var->Next;

        // Calculate pointer to next set of appended data
        Var = (PUEFI_VARIABLE)((INT_PTR)Var + nextOffset);

        // Loop if we have another entry or we haven't written size bytes yet
    } while ((nextOffset) && (dstPtr < limit));

Cleanup:
    if (BytesWritten) // or needed..
    {
        *BytesWritten = size + sizeof(VARIABLE_GET_RESULT);
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
    //  2. If !NV, just do it.
    //  3. If NV then mark deleted (clear guid) and run Next-> list
    //  4. TODO: DECIDE WHEN TO COLLAPSE NV (MAYBE ON DELETE, MAYBE NOT)
    return TEE_SUCCESS;
}

TEE_Result
AppendVariable(
    PUEFI_VARIABLE          Var,
    VARTYPE                 VarType,
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

        VarType - Which variable list is Var on?

        Attibutes - UEFI variable attributes

        ExtAttributes - Pointer to ExtendedAttributes (auth only)

        Data - Pointer to the data

        DataSize - Size in bytes of Data

    Returns:

        TEE_Result

--*/
{
    TEE_Result  status = TEE_SUCCESS;

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        PBYTE dstPtr = NULL;
        PBYTE oldPtr = NULL;
        UINT32 newSize = 0;

        // TODO: CHECK FOR OVERFLOW
        newSize = Var->DataSize + DataSize;

        // Attempt allocation
        if (!(dstPtr = TEE_Malloc(newSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // First, bring over existing variable data
        memmove(dstPtr, Var->Data, Var->DataSize);

        // Then copy appended data
        memmove(dstPtr + Var->DataSize, Data, DataSize);

        // Free up old allocation and update new size/ptr
        TEE_Free((PVOID)Var->Data);
        Var->DataSize = newSize;
        Var->Data = dstPtr;

        status = TEE_SUCCESS;
        goto Cleanup;
    }
    else {
        // Nope, append to existing non-volatile variable.

        PUEFI_VARIABLE apndVar = NULL, varPtr = NULL;
        PBYTE apndData = NULL;
        UINT32 apndSize = 0, extAttribLen = 0;

        // Calculate space required for additional data. (Note that 
        // we use a UEFI_VARIABLE as a container for appended data).
        apndSize = sizeof(UEFI_VARIABLE) + DataSize;

        // Is there enough room on the list and in NV?
        if ((apndSize > VarInfo[VarType].RemainingBytes) ||
            ((apndSize + s_nextFree) > s_nvLimit))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Ensure that we have consistency in args and var info
        if (ExtAttributes && (Var->ExtAttrib == 0))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Merge if we can
        apndVar = Var;
        while (apndVar->Next)
        {
            // Find last linked data entry
            apndVar = (PUEFI_VARIABLE)((INT_PTR)apndVar + apndVar->Next);
        }

        // Is apndVar adjacent to this variable entry?
        if (((INT_PTR)Var + Var->AllocSize) == (INT_PTR)apndVar)
        {
            // Yes, init pointer to appended data destination
            apndData = (PBYTE)((INT_PTR)Var + Var->Data + Var->DataSize);

            // Copy data
            memmove(apndData, Data, DataSize);

            // Update sizes (we know we're adding to the end of NV data)
            Var->AllocSize = Var->DataSize + DataSize;
            Var->DataSize += DataSize;

            // Done
            status = TEE_SUCCESS;
            goto Cleanup;
        }

        // Init pointers to new fields
        varPtr = apndVar;  // To link last entry, apndVar may not == Var
        apndVar = (PUEFI_VARIABLE)s_NV[s_nextFree];
        apndData = (PBYTE)((INT_PTR)apndVar + sizeof(UEFI_VARIABLE));

        // Init appended variable structure
        apndVar->List.Flink = apndVar->List.Blink = 0;
        apndVar->VendorGuid = Var->VendorGuid;
        apndVar->Attributes.Flags = Attributes.Flags;
        apndVar->NameSize = 0;
        apndVar->Name = 0;
        apndVar->AllocSize = sizeof(UEFI_VARIABLE) + DataSize;
        apndVar->ExtAttribSize = 0;
        apndVar->ExtAttrib = 0;
        apndVar->DataSize = DataSize;
        apndVar->Data = apndVar->Name + DataSize;  // Yes, it's zero


        // Copy data
        memmove(apndData, Data, DataSize);

        // Update extended attributes, if present
        if (ExtAttributes)
        {
            PEXTENDED_ATTRIBUTES extAttrib;

            // Sanity check sizes
            extAttrib = (PEXTENDED_ATTRIBUTES)((INT_PTR)Var + Var->ExtAttrib);
            extAttribLen = sizeof(EXTENDED_ATTRIBUTES) + ExtAttributes->PublicKey.DataSize;
            if (extAttribLen != (sizeof(EXTENDED_ATTRIBUTES) + extAttrib->PublicKey.DataSize))
            {
                status = TEE_ERROR_BAD_PARAMETERS;
                goto Cleanup;
            }

            // Copy new extended attribute data
            memmove(extAttrib, ExtAttributes, extAttribLen);
        }

        // Finally, link appended variable data
        Var->Next = s_nextFree;
    }
Cleanup:
    return status;
}

TEE_Result
ReplaceVariable(
    PUEFI_VARIABLE          Var,
    VARTYPE                 VarType,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtAttributes,
    PBYTE                   Data,
    UINT32                  DataSize
)
/*++

    Routine Description:

        Function for replacing value of an existing volatile variable

    Arguments:

        Var - Pointer to the variable's entry in memory.

        Attibutes - UEFI variable attributes

        ExtAttributes - Pointer to ExtendedAttributes (auth only)

        Data - Pointer to the data

        DataSize - Size in bytes of Data

    Returns:

        TEE_Result

--*/
{
    PBYTE srcPtr;
    PUEFI_VARIABLE dstPtr;
    INT_PTR nextOffset, limit;
    UINT32 length, canFit, remaining;
    TEE_Result  status = TEE_SUCCESS;

    // We don't implement authenticated volatile variables
    if (!(Attributes.NonVolatile) && ExtAttributes)
    {
        status = TEE_ERROR_NOT_IMPLEMENTED;
        goto Cleanup;
    }

    // Some parameter checking
    if (((Attributes.TimeBasedAuth) && !ExtAttributes) ||
        !(Attributes.TimeBasedAuth) && ExtAttributes)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        // Yes. Make sure varialbe doesn't indicate APPEND_WRITE.
        if (!(Attributes.AppendWrite))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // We're good, can we re-use this allocation?
        if (DataSize == Var->DataSize) {
            // Yes, skip malloc/free
            memmove(Var->Data, Data, DataSize);
            Var->Attributes.Flags = Attributes.Flags;
            goto Cleanup;
        }

        // No, attempt allocation
        if (!(dstPtr = TEE_Malloc(DataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Success, copy new entry.
        memmove(dstPtr, Data, DataSize);

        // Free old var data and update entry
        TEE_Free((PVOID)Var->Data);
        Var->Data = dstPtr;
        Var->DataSize = DataSize;
        Var->Attributes.Flags = Attributes.Flags;

        status = TEE_SUCCESS;
        goto Cleanup;
    }

    // No, replace existing non-volatile variable.

    // Calculate the amount of NV we already have for this variable
    canFit = MAX(Var->DataSize, Var->AllocSize);
    if (DataSize > canFit) {
        // We are increasing our allocation, make sure it will fit.
        length = DataSize - canFit;
        if ((length > VarInfo[VarType].RemainingBytes) ||
            (length + s_nextFree) > s_nvLimit)
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }
    }

    // Init for copy
    dstPtr = Var;   // Save off Var before we wreck it.
    srcPtr = Data;
    remaining = DataSize;
    limit = (INT_PTR)Data + DataSize;

    // Do the copy (accross appended data entries if necessary)
    do {
        // Determine length for copy
        canFit = Var->End - Var->Data;
        length = MIN(canFit, remaining);

        // Length is either the size of this entry or our remaining byte count
        memmove((PBYTE)((INT_PTR)Var + Var->Data), srcPtr, length);

        // Adjust remaining and source pointer
        remaining -= length;
        srcPtr += length;

        // Pickup offset to next set of appended data (may be zero)
        nextOffset = Var->Next;

        // Calculate pointer to next set of appended data
        Var = (PUEFI_VARIABLE)((INT_PTR)Var + nextOffset);

        // Loop if we have another entry and we haven't written DataSize bytes yet
    } while ((nextOffset) && (srcPtr < limit));

    // This should never happen, but if we overran our buffer then panic
    if (srcPtr > limit)
    {
        // TODO: SHOULD TEE_PANIC HERE, THIS SHOULD NEVER HAPPEN
        status = TEE_ERROR_OVERFLOW;
        goto Cleanup;
    }

    // Did we run out of space in this variable? If so, append the remaining bytes.
    if (srcPtr < limit)
    {
        // TODO: TEE_PANIC HERE IF nextOffset != 0 (TEE_ERROR_BAD_STATE)

        // Append on the rest
        status = AppendVariable(Var, VarType, Attributes, ExtAttributes, srcPtr, remaining);
    }
    else
    {
        // Data copy was successful, but is some cleanup necessary?
        if (nextOffset)
        {
            // If our next offset != 0 on what should be the last data entry, it's
            // because we 'replaced' the variable data with a smaller data size.
            // Clean up the excess appended data entries now.
            status = DeleteVariable(Var, VarType, Attributes);
        }
    }

    // On success update size
    if (status == TEE_SUCCESS)
    {
        dstPtr->DataSize = DataSize;
    }

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
    if (!GetVariableType(NULL, NULL, Attributes, &varType))
    {
        return;
    }

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
BOOLEAN
GetVariableType(
    PCWSTR      VarName,        // IN
    PCGUID      VendorGuid,     // IN
    ATTRIBUTES  Attributes,     // IN
    PVARTYPE    VarType         // OUT
)
/*++

    Routine Description:

        Function for determining Non-volatile variable type

    Arguments:

        VarName - Name of the variable being searched

        VendorGuid - GUID of the variable

        Attributes - UEFI attributes of the variable

        VarType - Storage for result

    Returns:

        TRUE - Success, VarType contains variable type

        FALSE - Appended or deleted data, VarType not updated

--*/
{
    // An empty attributes field or guid means this is appended/deleted data
    if (!(Attributes.Flags) || !memcmp(VendorGuid, &GUID_NULL, sizeof(GUID)))
    {
        return FALSE;
    }

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

    // None of the above (but assumed NonVolatile).
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