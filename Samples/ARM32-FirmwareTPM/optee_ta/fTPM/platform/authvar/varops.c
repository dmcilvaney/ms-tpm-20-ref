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

#include <varops.h>
#include <varmgmt.h>
#include <varauth.h>

// Secureboot variable guids
const GUID EfiGlobalDatabaseGUID = EFI_GLOBAL_VARIABLE;
const GUID EfiSecurityDatabaseGUID = EFI_IMAGE_SECURITY_DATABASE_GUID;

//
// AuthVar functions
//

TEE_Result
GetVariable(
    UINT32               GetParamSize,  // IN
    VARIABLE_GET_PARAM  *GetParam,      // IN
    UINT32              *GetReultSize,  // INOUT
    VARIABLE_GET_RESULT *GetResult      // OUT
)
/*++

    Routine Description:

        Function for implementing UEFI GetVariable operation

    Arguments:

        GetParamSize - Length in bytes of input buffer

        GetParam - Pointer to input buffer

        GetResultSize - Length in bytes of output buffer

        GetResult - Pointer to output buffer

    Returns:

        TEE_Result

--*/
{   
    VARTYPE varType;
    PWSTR varName;
    PUEFI_VARIABLE varPtr;
    GUID vendorGuid;
    UNICODE_STRING unicodeName;
    TEE_Result status = TEE_SUCCESS;

    // Validate parameters
    if (!(GetParam) || !(GetResult) || (GetParamSize  < sizeof(VARIABLE_GET_PARAM)))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Request validation
    if (!(GetReultSize) || (GetParam->Size != sizeof(VARIABLE_GET_PARAM)))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Size of result buffer
    if (*GetReultSize < sizeof(VARIABLE_QUERY_RESULT))
    {
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Validation of var name size
    if (!(GetParam->NameSize) || (GetParam->NameSize % sizeof(WCHAR)))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Guard against overflow with name string
    if (((GetParam->NameSize + sizeof(VARIABLE_GET_PARAM)) < GetParam->NameSize) ||
        (GetParam < (sizeof(VARIABLE_GET_PARAM) + GetParam->NameSize)))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Retreive (name, guid)
    varName = (PWSTR)(GetParam->Name);
    vendorGuid = GetParam->VendorGuid;

    // Init local name string
    memset(&unicodeName, 0, sizeof(unicodeName));
    unicodeName.Buffer = varName;
    unicodeName.Length = GetParam->NameSize - sizeof(WCHAR);
    unicodeName.MaximumLength = GetParam->NameSize;

    // Find the variable
    SearchList(&unicodeName, &vendorGuid, &varPtr, &varType);

    // Did we find it?
    if (!(varPtr))
    {
        // No.
        status = TEE_ERROR_ITEM_NOT_FOUND;
        goto Cleanup;
    }

    // Yes, go get it.
    RetrieveVariable(varPtr, GetResult, GetReultSize, NULL);
    status = TEE_SUCCESS;

Cleanup:
    return status;
}

TEE_Result
GetNextVariableName(
    UINT32                       GetNextParamSize,
    VARIABLE_GET_NEXT_PARAM     *GetNextParam,
    UINT32                      *GetNextResultSize,
    VARIABLE_GET_NEXT_RESULT    *GetNextResult
)
/*++

    Routine Description:

        Function implementing UEFI GetNextVariableName operation

    Arguments:

        GetNextParamSize - Length in bytes of input buffer

        GetNextParam - Pointer to input buffer

        GetNextResultSize - Length in bytes of output buffer

        GetNextResult - Pointer to output buffer

    Returns:

        TEE_Result

--*/
{  
    UNICODE_STRING unicodeName;
    GUID vendorGuid;
    PUEFI_VARIABLE varPtr, nextVar;
    PWSTR varName;
    UINT32 size, i;
    TEE_Result status;
    VARTYPE varType;
    USHORT varNameLen;


    // Validate parameters
    if (!(GetNextParam) || !(GetNextResult) || (GetNextParamSize < sizeof(VARIABLE_GET_NEXT_PARAM)))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Request validation
    if (!(GetNextResultSize) || (GetNextParam->Size != sizeof(VARIABLE_GET_NEXT_PARAM)))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Size of result buffer
    if (*GetNextResultSize < sizeof(VARIABLE_GET_NEXT_PARAM))
    {
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Init local name string
    memset(&unicodeName, 0, sizeof(unicodeName));

    // Pickup (name,guid)
    varNameLen = GetNextParam->NameSize;
    vendorGuid = GetNextParam->VendorGuid;

    // Init for search
    nextVar = NULL;

    // Is this the first request?
    if (!varNameLen)
    {
        // Yes, return first variable that can be found in any list
        for (i = 0; i < ARRAY_SIZE(VarInfo); i++)
        {
            if (!IsListEmpty(&VarInfo[i].Head))
            {
                // Pick up first variable
                nextVar = (PUEFI_VARIABLE)VarInfo[i].Head.Flink;
                break;
            }
        }
    }
    else
    {
        // Validation on name length (we already know it's non-zero)
        if (varNameLen % sizeof(WCHAR))
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Guard against overflow
        if (((varNameLen + sizeof(VARIABLE_GET_NEXT_PARAM)) < varNameLen) ||
            (GetNextParamSize < (sizeof(VARIABLE_GET_NEXT_PARAM) + varNameLen)))
        {

            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Init for variable search
        varName = (PWSTR)(GetNextParam->Name);
        unicodeName.Buffer = varName;
        unicodeName.Length = varName - sizeof(WCHAR);
        unicodeName.MaximumLength = varNameLen;

        // Get the next variable in the list
        SearchList(&unicodeName, &vendorGuid, &varPtr, &varType);

        // Did we find it?
        if (varPtr == NULL)
        {
            // No.
            status = TEE_ERROR_ITEM_NOT_FOUND;
            goto Cleanup;
        }

        // Yes. If this isn't the end of this list, get next.
        if (varPtr->List.Flink != &(VarInfo[varType].Head))
        {
            nextVar = (PUEFI_VARIABLE)varPtr->List.Flink;
        }
        else
        {
            // End of this list, move to the next category
            while (++varType != VTYPE_END)
            {
                if (!IsListEmpty(&(VarInfo[varType].Head)))
                {
                    nextVar = (PUEFI_VARIABLE)VarInfo[varType].Head.Flink;
                    break;
                }
            }
        }
    }

    // Are we done?
    if (nextVar == NULL)
    {
        status = TEE_ERROR_ITEM_NOT_FOUND;
        goto Cleanup;
    }

    // Prepare the result buffer with variable size, name, and guid
    // TODO: Guard against overflow here
    size = nextVar->NameSize + sizeof(VARIABLE_GET_NEXT_RESULT);
    if (size > *GetNextResultSize)
    {
        *GetNextResultSize = size;
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Update output buffer
    GetNextResult->NameSize = nextVar->NameSize;
    GetNextResult->VendorGuid = nextVar->VendorGuid;
    GetNextResult->Size = sizeof(VARIABLE_GET_NEXT_RESULT);
    memmove(GetNextResult->Name, 
        nextVar->Name, nextVar->NameSize);

    // Success, now update size field with bytes written
    *GetNextResultSize = sizeof(VARIABLE_GET_NEXT_RESULT) + nextVar->NameSize;
    status = TEE_SUCCESS;

Cleanup:
    return status;
}

TEE_Result
SetVariable(
    UINT32               SetParamSize,
    VARIABLE_SET_PARAM  *SetParam
)
{
    EXTENDED_ATTRIBUTES extAttrib;
    GUID vendorGuid;
    UNICODE_STRING unicodeName;
    PBYTE data, content;
    PWSTR varName;
    PUEFI_VARIABLE varPtr;
    TEE_Result status;
    UINT32 varNameSize;
    UINT32 dataSize, contentSize;
    UINT32 offsetLimit, totalSize;
    VARTYPE varType;
    ATTRIBUTES attrib;
    BOOLEAN duplicateFound;

    // Validate parameters
    if (!(SetParam)
        || (SetParamSize < sizeof(VARIABLE_SET_PARAM))
        || (SetParam->Size != sizeof(VARIABLE_SET_PARAM)))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // TODO: Detect overflow on DataSize
    dataSize = SetParam->DataSize;
    varNameSize = SetParam->NameSize;
    totalSize = sizeof(VARIABLE_SET_PARAM) + dataSize + varNameSize;
    offsetLimit = SetParamSize - sizeof(VARIABLE_SET_PARAM);

    // Validate sizes/offsets
    if ((totalSize < SetParamSize)
        || (SetParam->OffsetName > offsetLimit)
        || (SetParam->OffsetData > offsetLimit)
        || (SetParam->OffsetName + varNameSize > offsetLimit)
        || (SetParam->OffsetData + dataSize > offsetLimit))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // We expect the name of the variable before the data (if provided)
    if ((SetParam->DataSize) && (SetParam->OffsetName > SetParam->OffsetData))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Alignment check on variable name offset
    if (SetParam->OffsetName % sizeof(WCHAR))
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Now pickup parameter fields
    vendorGuid = SetParam->VendorGuid;
    attrib.Flags = SetParam->Attributes.Flags;
    varName = (PWSTR)(&SetParam->Payload[SetParam->OffsetName]);
    data = &SetParam->Payload[SetParam->OffsetData];

    // Don't consider NULL character in Length
    unicodeName.Buffer = varName;
    unicodeName.Length = varNameSize - sizeof(WCHAR);
    unicodeName.MaximumLength = varNameSize;

    // Attribute validation
    if ((attrib.Flags & (~EFI_KNOWN_ATTRIBUTES)) != 0)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (attrib.AuthWrite && attrib.TimeBasedAuth)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (attrib.AuthWrite || attrib.HwErrorRec)
    {
        return TEE_ERROR_NOT_IMPLEMENTED;
    }

    // Optimism, from here out
    status = TEE_SUCCESS;

    // Does the variable exist already?
    SearchList(&unicodeName, &vendorGuid, &varPtr, &varType);

    // Yes
    if (varPtr != NULL)
    {
        // Existing attributes may only differ in EFI_VARIABLE_APPEND_WRITE
        if (((attrib.Flags) ^ (varPtr->Attributes.Flags)) & ~(EFI_VARIABLE_APPEND_WRITE))
        {
            return TEE_ERROR_BAD_PARAMETERS;
        }

        // Once ExitBootServices() is performed..
        if ((fTPMIsRuntime) &&
            // ..only non-volatile variables with runtime access can be set
            !((varPtr->Attributes.RuntimeAccess) & (varPtr->Attributes.NonVolatile)))
        {
            return TEE_ERROR_ACCESS_DENIED;
        }

        // If this is an existing authenticated variable, perform security check
        if (varPtr->Attributes.TimeBasedAuth)
        {
            status = AuthenticateSetVariable(
                &unicodeName,
                &vendorGuid,
                varPtr,
                attrib,
                data,
                dataSize,
                &extAttrib,
                &duplicateFound,    // Indicates need to free() on content ptr
                &content,
                &contentSize);

            if (status != TEE_SUCCESS)
            {
                goto Cleanup;
            }

            data = content;
            dataSize = contentSize;
        }

        // Set() on a variable causes deletion when:
        //   1. Setting a data variable with no access attributes
        //   2. dataSize is zero unless write attribute(s) set
        if (!(attrib.Flags & EFI_ACCESS_ATTRIBUTES) ||
            (dataSize == 0) && !(attrib.Flags & EFI_WRITE_ATTRIBUTES))
        {
            status = DeleteVariable(varPtr, varType, attrib);
            goto Cleanup;
        }

        // Is this an append operation?
        if (attrib.AppendWrite)
        {
            status = AppendVariable(
                varPtr,
                attrib,
                &extAttrib,
                data,
                dataSize);
            goto Cleanup;
        }

        // No? Then we are attempting replacement. Once ExitBootServices() is
        // performed only non-volatile variables that have runtime access can
        // be set. Variables that are not non-volatile are read-only data
        // variables once ExitBootServices() is performed. Note that Caller is
        // responsible for following BS-implies-RT rule.
        if ((!(fTPMIsRuntime) && (attrib.BootService)) ||
            ((fTPMIsRuntime) && (attrib.RuntimeAccess) && (attrib.NonVolatile)))
        {
            status = ReplaceVariable(
                varPtr,
                attrib,
                &extAttrib,
                data,
                dataSize);
            goto Cleanup;
        }

        // If this case is not covered then one or more parameters are invalid.
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Variable doesn't already exist. Are we attempting deletion?
    if ((dataSize == 0) && !(attrib.Flags & EFI_WRITE_ATTRIBUTES))
    {
        status = TEE_ERROR_ITEM_NOT_FOUND;
        goto Cleanup;
    }

    // No, new variable creation. For NV, BS and BS+RT is allowed. RT-only is
    // invalid. However, caller is responsible for following BS-implies-RT rule.
    if ((attrib.NonVolatile) && (attrib.BootService))
    {
        if (attrib.TimeBasedAuth)
        {
            status = AuthenticateSetVariable(
                &unicodeName,
                &vendorGuid,
                NULL,
                attrib,
                data,
                dataSize,
                &extAttrib,
                &duplicateFound,
                &content,
                &contentSize);

            if (status != TEE_SUCCESS)
            {
                goto Cleanup;
            }

            data = content;
            dataSize = contentSize;
        }

        status = CreateVariable(
            &unicodeName,
            &vendorGuid,
            attrib,
            &extAttrib,
            dataSize,
            data);
        goto Cleanup;
    }

    // Cannot create new volatile variables at runtime
    if (!(attrib.NonVolatile) && !(fTPMIsRuntime) && (attrib.BootService))
    {
        // REVISIT: Implement volatile authenticated variables only if needed.
        if (attrib.TimeBasedAuth)
        {
            status = TEE_ERROR_NOT_IMPLEMENTED;
            goto Cleanup;
        }

        status = CreateVariable(
            &unicodeName,
            &vendorGuid,
            attrib,
            &extAttrib,
            dataSize,
            data);
        goto Cleanup;
    }

    // If this case is not covered then one or more parameters are invalid.
    status = TEE_ERROR_BAD_PARAMETERS;
    goto Cleanup;

Cleanup:
    // Need to clean up if we've updated an existing authenticated variable
    if (duplicateFound)
    {
        TEE_Free(content);
    }

    return status;
}

TEE_Result
QueryVariableInfo(
    UINT32                   QueryParamSize,    // IN
    VARIABLE_QUERY_PARAM    *QueryParam,        // IN
    UINT32                  *QueryResultSize,   // INOUT
    VARIABLE_QUERY_RESULT   *QueryResult        // OUT
)
/*++

    Routine Description:

        Function for implementing UEFI QueryVariableInfo operation

    Arguments:

        CallInfo - Tree Structure with input/output parameters

    Returns:

        TEE_Result

--*/
{
    TEE_Result  status = TEE_SUCCESS;
    ATTRIBUTES  attrib = { 0 };

    // Validate parameters
    if (!(QueryParam) || !(QueryResult) || (QueryParamSize  < sizeof(VARIABLE_QUERY_PARAM)))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Request validation
    if (!(QueryResultSize) || (QueryParam->Size != sizeof(VARIABLE_QUERY_PARAM)))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Size of result buffer
    if (*QueryResultSize < sizeof(VARIABLE_QUERY_RESULT))
    {
        status = TEE_ERROR_SHORT_BUFFER;
        goto Cleanup;
    }

    // Pick up query attributes
    attrib.Flags = QueryParam->Attributes.Flags;

    // Validate requested attributes
    if ((attrib.Flags & ~(EFI_KNOWN_ATTRIBUTES)) || ((fTPMIsRuntime) && (attrib.BootService))
        || (attrib.AuthWrite) || !(attrib.NonVolatile) || (attrib.HwErrorRec))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Note that since we are not provided a (name,guid) for a query, we cannot provide
    // information on secureboot variable storage.
    QueryByAttribute(attrib,
        &(QueryResult->MaximumVariableStorageSize),
        &(QueryResult->RemainingVariableStorageSize),
        &(QueryResult->MaximumVariableSize));

    // Success, update sizes
    QueryResult->Size = *QueryResultSize = sizeof(VARIABLE_QUERY_RESULT);
    status = TEE_SUCCESS;

Cleanup:
    return status;
}