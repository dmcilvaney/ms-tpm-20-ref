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
#include <NvMemoryLayout.h>

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
    VARTYPE i;
    BOOLEAN collapseList;

    // Sanity check on storage offset
    if (StartingOffset != s_nextFree)
    {
        //TODO TEE_Panic()
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

    for (i = 0; i < VTYPE_END; i++) {
        InitializeListHead(&(VarInfo[i].Head));
        DMSG("Head %d address is 0x%x", i, (uint32_t)&VarInfo[i].Head);
        DMSG("Head f:%x, Head b:%x", (uint32_t)VarInfo[i].Head.Flink, (uint32_t)VarInfo[i].Head.Blink);
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
        pVar->BaseAddress = (INT_PTR)pVar;
        guid = (PCGUID)&(pVar->VendorGuid);
        name = (PCWSTR)((pVar->NameOffset) + pVar->BaseAddress);

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
                INT_PTR curOffset = (pVar->BaseAddress - (INT_PTR)NvPtr);
                INT_PTR srcOffset = curOffset + pVar->AllocSize;
                INT_PTR dstOffset = curOffset;
                UINT32 curLen, size;

                // Prep for search
                pVar = (PUEFI_VARIABLE)srcOffset;
                curOffset = srcOffset;

                // Peek ahead and check if we can remove multiple deleted variables
                // in one pass.
                while ((curOffset < s_nextFree) && memcmp(&(pVar->VendorGuid), &GUID_NULL, sizeof(GUID)))
                {
                    // Accumulate size for move
                    curLen = pVar->AllocSize;
                    srcOffset += curLen;

                    // Next iteration
                    curOffset += curLen;
                    pVar = (PUEFI_VARIABLE)(pVar->BaseAddress + curLen);
                }

                // Close the gap and move the remainder of the data forward.
                size = s_nextFree - srcOffset;
                _plat__NvMemoryMove(srcOffset, dstOffset, size);
                s_nextFree -= size;

                // Reset pVar for next iteration
                pVar = (PUEFI_VARIABLE)((INT_PTR)NvPtr + dstOffset);
            }
        }

        // Compute pointer to next var
        pVar = (PUEFI_VARIABLE)(pVar->BaseAddress + pVar->AllocSize);
        DMSG("Doing %x is less than %x",((INT_PTR)pVar - (INT_PTR)NvPtr),s_nextFree);
    } while (((INT_PTR)pVar - (INT_PTR)NvPtr) < s_nextFree);

    // No need to commit NV changes to disk now, wait until actual data has been modified.
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
        //DMSG("search parameter failed!");
        return;
    }

    *Var = NULL;

    // Run the list(s)
    for (i = 0; i < ARRAY_SIZE(VarInfo); i++)
    {
        PLIST_ENTRY head = &VarInfo[i].Head;
        PLIST_ENTRY cur = head->Flink;
        //DMSG("Seraching type %d", i);
        //DMSG("Head:%x, cur:%x", head, cur);

        while ((cur) && (cur != head))
        {
            //DMSG("Comparing");
            if (CompareEntries(UnicodeName, VendorGuid, (PUEFI_VARIABLE)cur))
            {
                *Var = (PUEFI_VARIABLE)cur;
                *VarType = VarInfo[i].Type;
                //TODO: Why do we not break out early here?
            }

            cur = cur->Flink;
        }
    }
    //DMSG("Done compare");
    if(*Var) {
        DMSG("Found a match");
    } else {
        DMSG("No match");
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
        DMSG("volatile var");
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
        if (!(newStr  = TEE_Malloc(UnicodeName->MaximumLength * sizeof(wchar_t), TEE_USER_MEM_HINT_NO_FILL_ZERO)))
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

        // Pointers to name, etc. are proper memory addresses, 
        // not offsets inside the memory map
        newVar->BaseAddress = 0;

        // Init/copy variable name
        newVar->NameSize = UnicodeName->MaximumLength * sizeof(wchar_t);
        newVar->NameOffset = newStr;
        memmove(newStr, UnicodeName->Buffer, newVar->NameSize);

        DMSG("Unicode name is:");
        DHEXDUMP(newStr, newVar->NameSize);

        // Init/copy variable data
        newVar->DataSize = DataSize;
        newVar->DataOffset = newData;
        memmove(newData, Data, DataSize);

        DMSG("New  volatlie var is at 0x%x, data at 0x%x", (INT_PTR)newVar, (INT_PTR)newVar->DataOffset);
        DHEXDUMP(newVar->DataOffset, DataSize);
        DMSG("GUID");
        DHEXDUMP(&newVar->VendorGuid, sizeof(newVar->VendorGuid));

        // Note the lack of a check against ExtendedAttributes.
        // We do not implement authenticated volatile variables.

        DMSG("Updating list of type %d", VTYPE_VOLATILE);
        DMSG("at %x", (uint32_t)&VarInfo[VTYPE_VOLATILE].Head);
        DMSG("we have f=%x, t=%x", (uint32_t)VarInfo[VTYPE_VOLATILE].Head.Flink, (uint32_t)VarInfo[VTYPE_VOLATILE].Head.Blink);

        // Add it to the list
        InsertTailList(&(VarInfo[VTYPE_VOLATILE].Head), &newVar->List);

        DMSG("Now we have f=%x, t=%x", (uint32_t)VarInfo[VTYPE_VOLATILE].Head.Flink, (uint32_t)VarInfo[VTYPE_VOLATILE].Head.Blink);

        // Success
        status = TEE_SUCCESS;
        goto Cleanup;
    }
    else
    {
        // Nope, create new non-volatile variable.
        DMSG("non-volatile");
        // Which list is this variable destined for?
        if (!GetVariableType(UnicodeName->Buffer, VendorGuid, Attributes, &varType))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Get strlen of unicode name
        uStrLen = UnicodeName->MaximumLength * sizeof(wchar_t);

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

        DMSG("Storing 0x%x bytes (variable + name + data)", totalNv);

        // Is there enough room on this list and in NV?
        if ((totalNv + s_nextFree) > s_nvLimit)
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Init pointers to new fields
        DMSG("s_NV is at 0x%x", (uint32_t)s_NV);
        DMSG("offset is 0x%x", s_nextFree);
        newVar =    (PUEFI_VARIABLE)&(s_NV[s_nextFree]);
        DMSG("newVar: 0x%x", (uint32_t)newVar);
        newVar->BaseAddress = (INT_PTR)newVar;
        newStr = (PWSTR)((INT_PTR)newVar + sizeof(UEFI_VARIABLE));
        DMSG("New string is at 0x%x, with length 0x%x", (INT_PTR)newStr, uStrLen);
        newExt = (PEXTENDED_ATTRIBUTES)((INT_PTR)newStr + uStrLen);
        DMSG("New ext is at 0x%x, with length 0x%x", (INT_PTR)newExt, extAttribLen);
        newData = (PBYTE)((INT_PTR)newExt + extAttribLen);
        DMSG("New data is at 0x%x, with length 0x%x", (INT_PTR)newData, DataSize);

        DMSG("create");


        DMSG("vendorguid is 0x%x",(uint32_t)VendorGuid);
        // Init variable structure
        newVar->VendorGuid = *VendorGuid;
        newVar->Attributes.Flags = Attributes.Flags;
        newVar->NameSize = uStrLen;
        newVar->NameOffset = (INT_PTR)newStr - newVar->BaseAddress;
        DMSG("String offset is 0x%x", newVar->NameOffset);
        DMSG("create");
        // Copy name and data
        memmove(newStr, UnicodeName->Buffer, uStrLen);

        // Size of var structure before any appended data that may come later
        // Make sure all structures are aligned.
        newVar->AllocSize = ROUNDUP(totalNv, 8);
        DMSG("create");
        // Extended attributes, if necessary
        if (!extAttribLen)
        {
            // No extended attributes
            newVar->ExtAttribSize = 0;
            newVar->ExtAttribOffset = 0;
        }
        else
        {
            // Copy extended attributes
            newVar->ExtAttribSize = extAttribLen;
            newVar->ExtAttribOffset = (INT_PTR)newExt - newVar->BaseAddress;
            memmove(newExt, ExtAttributes, extAttribLen);
        }
        DMSG("create");
        // Data fields
        newVar->DataSize = DataSize;
        newVar->DataOffset = (INT_PTR)newData - newVar->BaseAddress;
        memmove(newData, Data, DataSize);

        // Creating this var we don't yet have appended data
        newVar->NextOffset = NULL;
        DMSG("create");
        // We've touched NV so, write back.
        _plat__MarkDirtyBlocks(newVar->BaseAddress, newVar->AllocSize);
        _plat__NvCommit();

        DMSG("Updating s_nextFree from 0x%x by incrementing %x (%x)", s_nextFree, newVar->AllocSize, totalNv);
        DMSG("0x%x -> 0x%x", (INT_PTR)s_NV + s_nextFree, (INT_PTR)s_NV + s_nextFree + newVar->AllocSize);
        // Update offset to next free byte alligned to 64 bits
        s_nextFree += newVar->AllocSize;
        DMSG("create");
        NV_AUTHVAR_STATE authVarState;
		authVarState.NvEnd = s_nextFree;
		_admin__SaveAuthVarState(&authVarState);

        DMSG("Updating list of type %d", varType);
        DMSG("at %x we have value %x", &VarInfo[varType].Head, VarInfo[varType].Head);

        // Update the in-memory list
        InsertTailList(&VarInfo[varType].Head, &newVar->List);
        DMSG("Done insert");
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
    PUEFI_VARIABLE varIter;
    UINT32 size, length;
    TEE_Result status = TEE_SUCCESS;

    DMSG("ret");
    DMSG("Getting value from 0x%x", (uint32_t)Var);

    // Detect integer overflow
    if (((UINT32)ResultBuf + ResultBufLen) < (UINT32)ResultBuf)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    //Calculate the total size required
    size = 0;
    varIter = Var;
    do {
        DMSG("Adding size 0x%x", varIter->DataSize);
        DMSG("Next is 0x%x", varIter->NextOffset);
        size += varIter->DataSize;
        nextOffset = varIter->NextOffset;
        varIter = (PUEFI_VARIABLE)(varIter->BaseAddress + nextOffset);
    } while ((nextOffset));
    DMSG("Total size is 0x%x", size);

    DMSG("ResultBufLen:0x%x, we want to store 0x%x", ResultBufLen, (size + sizeof(VARIABLE_GET_RESULT)));

    if (ResultBufLen < (size + sizeof(VARIABLE_GET_RESULT)))
    {
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

DMSG("ret");
    // Copy variable data
    ResultBuf->Attributes = Var->Attributes.Flags;
    ResultBuf->DataSize = size;
    ResultBuf->Size = sizeof(VARIABLE_GET_RESULT);
DMSG("ret");
    // Init for copy
    dstPtr = ResultBuf->Data;
    limit = (INT_PTR)dstPtr + ResultBufLen;
DMSG("ret");
    // Do the copy (accross appended data entries if necessary)
    varIter = Var;
    do {
        // Calculate length and copy data
        length = varIter->DataSize;

        DMSG("Data:0x%x", varIter->DataOffset + varIter->BaseAddress);
        DMSG("ret");
        DMSG("COpying 0x%x bytes from 0x%x to 0x%x",length, varIter->DataOffset + varIter->BaseAddress, dstPtr);
        memcpy(dstPtr, varIter->DataOffset + varIter->BaseAddress, length);
        DMSG("ret");
        // Adjust destination pointer
        dstPtr += length;

        // Pickup offset to next set of appended data (may be zero)
        nextOffset = varIter->NextOffset;

        // Calculate pointer to next set of appended data
        varIter = (PUEFI_VARIABLE)(varIter->BaseAddress + nextOffset);

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
    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        TEE_Free(Var->DataOffset);
        TEE_Free(Var->NameOffset);
        TEE_Free(Var);
    } else {
        // First clear any further appended elements.
        if(Var->NextOffset) {
            DeleteVariable((PUEFI_VARIABLE)(Var->BaseAddress + Var->NextOffset),
                            VarType,
                            Attributes);
        }
        DMSG("Clearing memory at 0x%x (offset 0x%x, + 0x%x)",(INT_PTR)Var->BaseAddress, (Var->BaseAddress) - (INT_PTR)s_NV, Var->AllocSize);
        _plat__NvMemoryClear((Var->BaseAddress) - (INT_PTR)s_NV, Var->AllocSize);
    }

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
    DMSG("Append variable");

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        DMSG("Volatile append");
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
        // NonVolatile variables always have base address of 0, no need to
        // add it.
        memmove(dstPtr, Var->DataOffset, Var->DataSize);

        // Then copy appended data
        memmove(dstPtr + Var->DataSize, Data, DataSize);

        // Free up old allocation and update new size/ptr
        TEE_Free((PVOID)Var->DataOffset);
        Var->DataSize = newSize;
        Var->DataOffset = dstPtr;

        status = TEE_SUCCESS;
        goto Cleanup;
    }
    else {
        // Nope, append to existing non-volatile variable.
        DMSG("Non volatile append");

        PUEFI_VARIABLE varPtr = NULL, lastVar = NULL, newVar = NULL;
        PBYTE apndData = NULL;
        UINT32 apndSize = 0, extAttribLen = 0;
        UINT32 availableSize = 0;

        // Calculate space required for additional data. (Note that 
        // we use a UEFI_VARIABLE as a container for appended data).
        apndSize = sizeof(UEFI_VARIABLE) + DataSize;
        DMSG("We need to add 0x%x bytes (%x + %x)", apndSize, sizeof(UEFI_VARIABLE), DataSize);

        // Is there enough room on the list and in NV?
        if ((apndSize + s_nextFree) > s_nvLimit)
        {
            DMSG("No room");
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }

        // Ensure that we have consistency in args and var info
        if (ExtAttributes && (Var->ExtAttribOffset == 0))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Find the end of the chain
        lastVar = varPtr = Var;
        DMSG("LastVar next offset = 0x%x", lastVar->NextOffset);
        while (lastVar->NextOffset)
        {
            DMSG("LastVar next offset = 0x%x", lastVar->NextOffset);
            // Find last two data entries
            varPtr = lastVar;
            lastVar = (PUEFI_VARIABLE)(lastVar->BaseAddress + lastVar->NextOffset);
            DMSG("lastVar @ 0x%x, varPtr @ 0x%x,");
        }

        //TODO: We can just append to the last remaining variable if its at the end of memory?
        // Do we care?

        // Is lastVar adjacent to varPtr?
        // We should attempt to merge entries which are now adjacent due to prior
        // deletions.
        if ((varPtr->BaseAddress + varPtr->AllocSize) == (INT_PTR)lastVar)
        {
            DMSG("Adjacent, try to merge");
            // Yes, init pointer to appended data destination
            DMSG("vp:0x%x, do:0x%x, ds: 0x%x", varPtr->BaseAddress, varPtr->DataOffset, varPtr->DataSize);
            apndData = varPtr->BaseAddress + varPtr->DataOffset + varPtr->DataSize;

            // Mark the last element as unused
            memmove(&lastVar->VendorGuid, &GUID_NULL, sizeof(GUID));
            memset(&lastVar->Attributes, 0, sizeof(lastVar->Attributes));
            varPtr->NextOffset = NULL;

            // How much size is there between the end of the penultimate element's data, and the
            // end of the space allocated for the last element.
            DMSG("lv:0x%x, as:0x%x, end of previous data: 0x%x",lastVar->BaseAddress, lastVar->AllocSize, (INT_PTR)apndData);
            availableSize = (lastVar->BaseAddress + lastVar->AllocSize) - (INT_PTR)apndData;
            apndSize = MIN(availableSize, DataSize);

            DMSG("We can append 0x%x bytes by merging, and we will use 0x%x", availableSize, apndSize);

            // Copy data
            memmove(apndData, Data, apndSize);

            Data += apndSize;
            DataSize -= apndSize;

            // Update sizes (we know we're adding to the end of NV data)
            DMSG("varPtr had 0x%x bytes of data", varPtr->DataSize);
            varPtr->DataSize += apndSize;
            varPtr->AllocSize = ROUNDUP(varPtr->DataOffset + varPtr->DataSize, 8);
            DMSG("varPtr now has 0x%x bytes of data", varPtr->DataSize);

            // Update the NV memory
            _plat__MarkDirtyBlocks(varPtr->BaseAddress, varPtr->AllocSize);

            lastVar = varPtr;
        }

        // There may be data left which could not be included in the merged elements
        if (DataSize > 0) {

            DMSG("Add new variable to hold extra data");
        
            // Need to create a new structure to hold the data.
            // Init pointers to new fields
            newVar = (PUEFI_VARIABLE)&s_NV[s_nextFree];
            DMSG("New variable at 0x%x", (INT_PTR)newVar);

            newVar->BaseAddress = (INT_PTR)newVar;
            newVar->List.Flink = newVar->List.Blink = 0;
            newVar->VendorGuid = Var->VendorGuid;
            newVar->Attributes.Flags = Attributes.Flags;
            newVar->NameSize = 0;
            newVar->NameOffset = 0;
            newVar->AllocSize = ROUNDUP(sizeof(UEFI_VARIABLE) + DataSize, 8);
            newVar->ExtAttribSize = 0;
            newVar->ExtAttribOffset = 0;
            newVar->DataSize = DataSize;
            apndData = (PBYTE)(newVar->BaseAddress + sizeof(UEFI_VARIABLE));

            newVar->DataOffset = (INT_PTR)apndData - newVar->BaseAddress;
            DMSG("Updating tail pointer in newVar to point to 0x%x (0x%x)", newVar->DataOffset + newVar->BaseAddress, newVar->DataOffset);

            // Copy data
            memmove(apndData, Data, DataSize);

            // Update extended attributes, if present
            if (ExtAttributes)
            {
                PEXTENDED_ATTRIBUTES extAttrib;

                // Sanity check sizes
                extAttrib = (PEXTENDED_ATTRIBUTES)(Var->BaseAddress + Var->ExtAttribOffset);
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
            lastVar->NextOffset = newVar->BaseAddress - lastVar->BaseAddress;

            // Update the NV memory
            _plat__MarkDirtyBlocks(newVar->BaseAddress, newVar->AllocSize);

            s_nextFree += newVar->AllocSize;
            NV_AUTHVAR_STATE authVarState;
            authVarState.NvEnd = s_nextFree;
            _admin__SaveAuthVarState(&authVarState);
        }
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

    DMSG("REplacing variable at 0x%x", (INT_PTR)Var);

    // 
    if (*(UINT64*)ExtAttributes == 0) {
        ExtAttributes = NULL;
    }

    // We don't implement authenticated volatile variables
    if (!(Attributes.NonVolatile) && ExtAttributes)
    {
        DMSG("replace error");
        status = TEE_ERROR_NOT_IMPLEMENTED;
        goto Cleanup;
    }

    // Some parameter checking
    if (((Attributes.TimeBasedAuth) && !ExtAttributes) ||
        !(Attributes.TimeBasedAuth) && ExtAttributes)
    {
        DMSG("replace error");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // First, is this a volatile variable?
    if (!(Attributes.NonVolatile))
    {
        // Yes. Make sure varialbe doesn't indicate APPEND_WRITE.
        if (!(Attributes.AppendWrite))
        {
            DMSG("replace error");
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // We're good, can we re-use this allocation?
        if (DataSize <= Var->DataSize) {
            // Yes, skip malloc/free
            memmove(Var->DataOffset, Data, DataSize);
            Var->DataSize = DataSize;
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
        TEE_Free((PVOID)Var->DataOffset);
        Var->DataOffset = dstPtr;
        Var->DataSize = DataSize;
        Var->Attributes.Flags = Attributes.Flags;

        status = TEE_SUCCESS;
        goto Cleanup;
    }

    // No, replace existing non-volatile variable.

    // Calculate the amount of NV we already have for this variable
    canFit = Var->AllocSize - Var->DataOffset;
    DMSG("Alloc: 0x%x, DS: 0x%x, DO: 0x%x", Var->AllocSize, Var->DataSize, Var->DataOffset);
    if (DataSize > canFit) {
        // We are increasing our allocation, make sure a new variable will fit.
        length = DataSize - canFit;
        if ((Var->AllocSize + length + s_nextFree) > s_nvLimit)
        {
            status = TEE_ERROR_OUT_OF_MEMORY;
            goto Cleanup;
        }
    }

    DMSG("non-volatile replace");

    // Init for copy
    srcPtr = Data;
    remaining = DataSize;
    limit = (INT_PTR)Data + DataSize;

    DMSG("Want to replace with %d bytes of new data", remaining);

    // Do the copy (across appended data entries if necessary)
    do {
        // Determine available space to copy to in the current variable
        canFit = Var->AllocSize - Var->DataOffset;
        DMSG("WE can fit %d bytes into the current variable", canFit);
        // Length is either the size of this entry or our remaining byte count
        length = MIN(canFit, remaining);

        DMSG("Moving %d bytes into the existing variable", length);

        memmove((PBYTE)(Var->BaseAddress + Var->DataOffset), srcPtr, length);
        DMSG("Stomping over 0x%x ot 0x%x", (Var->BaseAddress + Var->DataOffset),(Var->BaseAddress + Var->DataOffset) + length - 1);
        Var->DataSize = length;

        // Adjust remaining and source pointer
        remaining -= length;
        srcPtr += length;

        // Pickup offset to next set of appended data (may be zero)
        nextOffset = Var->NextOffset;

        if(nextOffset) {
            DMSG("Continuing on to next element");
            // Calculate pointer to next set of appended data
            Var = (PUEFI_VARIABLE)(Var->BaseAddress + nextOffset);
        }

        // Loop if we have another entry and we haven't written DataSize bytes yet
    } while ((nextOffset) && (srcPtr < limit));

    // This should never happen, but if we overran our buffer then panic
    if (srcPtr > limit)
    {
        // TODO: SHOULD TEE_PANIC HERE, THIS SHOULD NEVER HAPPEN
        status = TEE_ERROR_OVERFLOW;
        TEE_Panic(TEE_ERROR_OVERFLOW);
        goto Cleanup;
    }

    // Did we run out of space in this variable? If so, append the remaining bytes.
    if (srcPtr < limit)
    {
        // TODO: TEE_PANIC HERE IF nextOffset != 0 (TEE_ERROR_BAD_STATE)
        DMSG("Append a new variable to the end of the list");

        // Append on the rest
        status = AppendVariable(Var, VarType, Attributes, ExtAttributes, srcPtr, remaining);
    }
    else
    {
        DMSG("We managed to fit it all");
        // Data copy was successful, but is some cleanup necessary?
        if (nextOffset)
        {

            // If our next offset != 0 on what should be the last data entry, it's
            // because we 'replaced' the variable data with a smaller data size.
            // Clean up the excess appended data entries now. If there is a nextOffset
            // Var will already point to the next element in the list.
            status = DeleteVariable(Var, VarType, Attributes);
            _plat__NvCommit();
            Var->NextOffset = NULL;
        }
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
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    if (RemainingVarStorage)
    {
        *RemainingVarStorage = 0;
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    if (MaxVarSize)
    {
        *MaxVarSize = 0;
        TEE_Panic(TEE_ERROR_BAD_STATE);
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

    //DMSG("Unicode name:");
    //DHEXDUMP(Name->Buffer, Name->MaximumLength);
    //DMSG("Target name at 0x%x + 0x%x = 0x%x:",Var->BaseAddress , Var->NameOffset, Var->BaseAddress + Var->NameOffset);
    //DHEXDUMP(Var->BaseAddress + Var->NameOffset, Var->NameSize);

    //DMSG("Comparing GUIDs at 0x%x and 0x%x", (uint32_t)Guid, (uint32_t)&Var->VendorGuid);
    //DHEXDUMP(&Var->VendorGuid, sizeof(Var->VendorGuid));
    // First, matching GUIDS?
    if (memcmp(Guid, &Var->VendorGuid, sizeof(GUID)) == 0)
    {
        //DMSG("Same");
        //DMSG("Mlengh = %d, SearchLengh = %d, checklength = %d", Name->MaximumLength, wcslen(Name->Buffer), wcslen(Var->BaseAddress + Var->NameOffset));
        // Ok, name strings of the same length?
        if (wcslen(Name->Buffer) == wcslen(Var->BaseAddress + Var->NameOffset))
        {
            //DMSG("Comparing Names at 0x%x and 0x%x", (uint32_t)Name->Buffer, Var->BaseAddress + (uint32_t)Var->NameOffset);
            // Yes, do they match? (case sensitive!)
            if (wcscmp(Name->Buffer, Var->BaseAddress + Var->NameOffset) == 0)
            {
                // Win.
                //DMSG("Match!");
                retVal = TRUE;
            }
        }
    }
    //if(!retVal) {
        //DMSG("No Match!");
    //}
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
        return TRUE;
    }

    // Runtime Auth?
    if ((Attributes.RuntimeAccess) && (Attributes.TimeBasedAuth))
    {
        *VarType = VTYPE_PVT_AUTHENTICATED;
        return TRUE;
    }
    
    // Boot only?
    if ((Attributes.BootService) && !(Attributes.RuntimeAccess))
    {
        *VarType = VTYPE_BOOT;
        return TRUE;
    }

    // None of the above (but assumed NonVolatile).
    *VarType = VTYPE_GENERAL;
    return TRUE;
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