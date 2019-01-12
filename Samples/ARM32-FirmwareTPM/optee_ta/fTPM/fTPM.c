/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
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

#define STR_TRACE_USER_TA "fTPM"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <varops.h>
#include "fTPM.h"

#define TA_ALL_PARAM_TYPE(type) TEE_PARAM_TYPES(type, type, type, type)

//
// Initialization
//
bool fTPMInitialized = false;

//
// ExitBootServices called?
//
bool fTPMIsRuntime = false;

//
// Local (SW) command buffer
//
static uint8_t fTPMCommand[MAX_COMMAND_SIZE];

//
// A subset of TPM return codes (see TpmTypes.h)
//
typedef uint32_t TPM_RC;
#define RC_VER1             (TPM_RC) (0x100)
#define TPM_RC_SUCCESS      (TPM_RC) (0x000)
#define TPM_RC_FAILURE      (TPM_RC) (RC_VER1+0x001)

//
// Helper functions for byte ordering of TPM commands/responses
//
static uint16_t SwapBytes16(uint16_t Value)
{
    return (uint16_t)((Value << 8) | (Value >> 8));
}

static uint32_t SwapBytes32(uint32_t Value)
{
    uint32_t  LowerBytes;
    uint32_t  HigherBytes;

    LowerBytes = (uint32_t)SwapBytes16((uint16_t)Value);
    HigherBytes = (uint32_t)SwapBytes16((uint16_t)(Value >> 16));

    return (LowerBytes << 16 | HigherBytes);
}

//
// Helper function to read response codes from TPM responses
//
static uint32_t fTPMResponseCode(uint32_t ResponseSize, 
                                 uint8_t *ResponseBuffer)
{
    uint32_t ResponseCode;
    union {
        uint32_t Data;
        uint8_t Index[4];
    } Value;

    // In case of too-small response size, assume failure.
    if (ResponseSize < 0xA) {
        return TPM_RC_FAILURE;
    }

    Value.Index[0] = ResponseBuffer[6];
    Value.Index[1] = ResponseBuffer[7];
    Value.Index[2] = ResponseBuffer[8];
    Value.Index[3] = ResponseBuffer[9];
    ResponseCode = SwapBytes32(Value.Data);

    return ResponseCode;
}

// 
// Called when TA instance is created. This is the first call to the TA.
// 
TEE_Result TA_CreateEntryPoint(void)
{
    #define STARTUP_SIZE 0x0C

    uint8_t startupClear[STARTUP_SIZE] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c,
                                           0x00, 0x00, 0x01, 0x44, 0x00, 0x00 };
    uint8_t startupState[STARTUP_SIZE] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c,
                                           0x00, 0x00, 0x01, 0x44, 0x00, 0x01 };
    uint32_t respLen;
    uint8_t *respBuf;

    // If we've been here before, don't init again.
    if (fTPMInitialized) {
        // We may have had TA_DestroyEntryPoint called but we didn't 
        // actually get torn down. Re-NVEnable, just in case.
        if (_plat__NVEnable(NULL) == 0) {
            TEE_Panic(TEE_ERROR_BAD_STATE);
        }
        return TEE_SUCCESS;
    }

    // Initialize NV admin state
    _admin__NvInitState();

    // If we fail to open fTPM storage we cannot continue.
    if (_plat__NVEnable(NULL) == 0) {
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    // This only occurs when there is no previous NV state, i.e., on first
    // boot, after recovering from data loss, we reset the platform, etc.
    if (_plat__NvNeedsManufacture()) {
        DMSG("TPM_Manufacture\n");
        TPM_Manufacture(1);
    }

    // "Power-On" the platform
    _plat__Signal_PowerOn();

    // Internal init for reference implementation
    _TPM_Init();

    // Startup with state
    if (g_chipFlags.fields.TpmStatePresent) {

        // Re-use request buffer for response (ignored)
        respBuf = startupState;
        respLen = STARTUP_SIZE;

        ExecuteCommand(STARTUP_SIZE, startupState, &respLen, &respBuf);
        if (fTPMResponseCode(respLen, respBuf) == TPM_RC_SUCCESS) {
            goto AuthVars;
        }

        goto Clear;
    }

Clear:
    // Re-use request buffer for response (ignored)
    respBuf = startupClear;
    respLen = STARTUP_SIZE;

    // Fall back to a Startup Clear
    ExecuteCommand(STARTUP_SIZE, startupClear, &respLen, &respBuf);

AuthVars:
    // Init is complete, indicate so in fTPM admin state.
    g_chipFlags.fields.TpmStatePresent = 1;
    _admin__SaveChipFlags();

    // TPM Init is done, now do AuthVars
    if (_plat__NVInitAuthVar() == 0) {
        TEE_Panic(TEE_ERROR_BAD_STATE);
    }

    // Initialization complete
    fTPMInitialized = true;

    DMSG("Done init!");

    return TEE_SUCCESS;
}


// 
// Called when TA instance destroyed.  This is the last call in the TA.
// 
void TA_DestroyEntryPoint(void)
{
    // We should only see this called after the OS has shutdown and there
    // will be no further commands sent to the TPM. Right now, just close
    // our storage object, becasue the TPM driver should have already
    // shutdown cleanly.
    _plat__NVDisable();
    return;
}


// 
// Called when a new session is opened to the TA.
// 
TEE_Result TA_OpenSessionEntryPoint(uint32_t    param_types,
                                    TEE_Param   params[4],
                                    void        **sess_ctx)
{
    uint32_t exp_param_types = TA_ALL_PARAM_TYPE(TEE_PARAM_TYPE_NONE);
    DMSG("Open session");

    // Unreferenced parameters
    UNREFERENCED_PARAMETER(params);
    UNREFERENCED_PARAMETER(sess_ctx);

    // Validate parameter types
    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

//    // Only one active session to the fTPM is permitted
//    if (fTPMSessionActive) {
//        return TEE_ERROR_ACCESS_CONFLICT;
//    }
//
//    // Active session
//    fTPMSessionActive = true;

    // If return value != TEE_SUCCESS the session will not be created.
    return TEE_SUCCESS;
}


//
// Called when a session is closed.
//
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    // Unused parameter(s)
    UNREFERENCED_PARAMETER(sess_ctx);

    // Clear active session
//    if (fTPMSessionActive) {
//        fTPMSessionActive = false;
//    }
}

//
// Called to handle command submission.
//
static TEE_Result fTPM_Submit_Command(uint32_t  param_types,
                                      TEE_Param params[4]
)
{
    uint8_t *cmdBuf, *respBuf;
    uint32_t cmdLen, respLen;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_INOUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);

    DMSG("fTPM submit command"); 
    // Validate parameter types
    if (param_types != exp_param_types) {
#ifdef fTPMDebug
        IMSG("Bad param type(s)\n");
#endif
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Sanity check our buffer sizes
    if ((params[0].memref.size == 0) ||
        (params[1].memref.size == 0) ||
        (params[0].memref.size > MAX_COMMAND_SIZE) ||
        (params[1].memref.size > MAX_RESPONSE_SIZE)) {
#ifdef fTPMDebug
        IMSG("Bad param size(s)\n");
#endif
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // Copy command locally
    memcpy(fTPMCommand, params[0].memref.buffer, params[0].memref.size);

    // Pull the command length from the actual TPM command. The memref size
    // field descibes the buffer containing the command, not the command.
    cmdBuf = fTPMCommand;
    cmdLen = BYTE_ARRAY_TO_UINT32((uint8_t *)&(cmdBuf[2]));
    // Sanity check cmd length included in TPM command
    if (cmdLen > params[0].memref.size) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    respBuf = (uint8_t *)(params[1].memref.buffer);
    respLen = params[1].memref.size;
    // Check if this is a PPI Command
    if (!_admin__PPICommand(cmdLen, cmdBuf, &respLen, &respBuf)) {
        // If not, pass through to TPM
        ExecuteCommand(cmdLen, cmdBuf, &respLen, &respBuf);
    }
    // Unfortunately, this cannot be done until after we have our response in
    // hand. We will, however, make an effort to return at least a portion of
    // the response along with TEE_ERROR_SHORT_BUFFER.
    if (respLen > params[1].memref.size)
    {
#ifdef fTPMDebug
        IMSG("Insufficient buffer length RS: 0x%x > BL: 0x%x\n", respLen, params[1].memref.size);
#endif
        return TEE_ERROR_SHORT_BUFFER;
    } 
#ifdef fTPMDebug
    DMSG("Success, RS: 0x%x\n", respLen);
#endif

    return TEE_SUCCESS;
}

//
// Called to handle PPI commands
//
static TEE_Result fTPM_Emulate_PPI(uint32_t  param_types,
                                   TEE_Param params[4]
)
{
    uint8_t *cmdBuf, *respBuf;
    uint32_t cmdLen, respLen;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                               TEE_PARAM_TYPE_MEMREF_INOUT,
                               TEE_PARAM_TYPE_NONE,
                               TEE_PARAM_TYPE_NONE);

    // Validate parameter types
    if (param_types != exp_param_types) {
#ifdef fTPMDebug
        IMSG("Bad param type(s)\n");
#endif
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Sanity check our buffer sizes
    if ((params[0].memref.size == 0) ||
        (params[1].memref.size == 0) ||
        (params[0].memref.size > MAX_COMMAND_SIZE) ||
        (params[1].memref.size > MAX_RESPONSE_SIZE)) {
#ifdef fTPMDebug
        IMSG("Bad param size(s)\n");
#endif
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Copy command locally
    memcpy(fTPMCommand, params[0].memref.buffer, params[0].memref.size);

    cmdBuf = fTPMCommand;
    cmdLen = params[0].memref.size;

    respBuf = (uint8_t *)(params[1].memref.buffer);
    respLen = params[1].memref.size;

    // Pass along to platform PPI processing
    if (_admin__PPIRequest(cmdLen, cmdBuf, &respLen, &respBuf)) {
#ifdef fTPMDebug
        DMSG("Handled PPI command via TA interface\n");
#endif
    }
    else {
#ifdef fTPMDebug
        IMSG("Failed to handle PPI command via TA interface\n");
#endif
    }

    if (respLen > params[1].memref.size) {
#ifdef fTPMDebug
        IMSG("Insufficient buffer length RS: 0x%x > BL: 0x%x\n", respLen, params[1].memref.size);
#endif
        return TEE_ERROR_SHORT_BUFFER;
    }

    params[1].memref.size = respLen;
    return TEE_SUCCESS;
}

//
// Get Authenticated Variable
//
static TEE_Result fTPM_AuthVar_Get(
    uint32_t  ParamTypes,
    TEE_Param Params[4]
)
{
    VARIABLE_GET_PARAM  *GetParam;
    VARIABLE_GET_RESULT *GetResult;
    uint32_t    GetParamSize;
    uint32_t    GetResultSize;
    uint32_t    ExpectedTypes;
    TEE_Result  Status;

    ExpectedTypes = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE);

    // TODO: Check that we're init'ed first

    // Validate parameter types
    if (ParamTypes != ExpectedTypes) {
        DMSG("fTPM_AuthVar_Get: bad param types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // REVISIT: Validate parameters here or in GetVariable?
    GetParam = (VARIABLE_GET_PARAM *)Params[0].memref.buffer;
    GetParamSize = Params[0].memref.size;

    GetResult = (VARIABLE_GET_RESULT *)Params[1].memref.buffer;
    GetResultSize = Params[1].memref.size;

    // Call VarOps
    Status = GetVariable(GetParamSize, GetParam, &GetResultSize, GetResult);
    DMSG("Get result 0x%x size: 0x%x", Status, GetResultSize);

    // Authvars driver expects TEE_SUCCESS, TEE_ERROR_SHORT_BUFFER,
    // or TEEC_ERROR_ITEM_NOT_FOUND as a return value. All other values
    // are handled as errors. Return values are also passed back through
    // parameter 2b to be handled by the command specific part of the driver.
    Params[2].value.a = GetResultSize;
    Params[2].value.b = Status;

    return Status;
}

//
// Get Next Authenticated Variable
//
static TEE_Result fTPM_AuthVar_GetNext(
    uint32_t  ParamTypes,
    TEE_Param Params[4]
)
{
    VARIABLE_GET_NEXT_PARAM     *GetNextParam;
    VARIABLE_GET_NEXT_RESULT    *GetNextResult;
    uint32_t    GetNextParamSize;
    uint32_t    GetNextResultSize;
    uint32_t    ExpectedTypes;
    TEE_Result  Status;

    ExpectedTypes = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE);

    // Validate parameter types
    // TODO: Right now we're ignoring the output value (param[2]).
    if (ParamTypes != ExpectedTypes) {
        IMSG("fTPM_AuthVar_Get: bad param types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // REVISIT: Validate parameters here or in GetVariable?
    GetNextParam = (VARIABLE_GET_NEXT_PARAM *)Params[0].memref.buffer;
    GetNextParamSize = Params[0].memref.size;

    GetNextResult = (VARIABLE_GET_RESULT *)Params[1].memref.buffer;
    GetNextResultSize = Params[1].memref.size;

    // TODO: Check that we're init'ed first

    // Call VarOps
    Status = GetNextVariableName(GetNextParamSize, GetNextParam, &GetNextResultSize, GetNextResult);

    Params[2].value.a = GetNextResultSize;

    // Authvars driver expects TEE_SUCCESS, TEE_ERROR_SHORT_BUFFER,
    // or TEEC_ERROR_ITEM_NOT_FOUND as a return value. All other values
    // are handled as errors. Return values are also passed  back through
    // parameter 2b to be handled by the command specific part of the driver.
    Params[2].value.b = Status;

    return Status;
}

//
// Set Authenticated Variable
//
static TEE_Result fTPM_AuthVar_Set(
    uint32_t  ParamTypes,
    TEE_Param Params[4]
)
{
    VARIABLE_SET_PARAM  *SetParam;
    uint32_t    SetParamSize;
    uint32_t    ExpectedTypes;
    TEE_Result  Status;

    DMSG("AV cmd");

    ExpectedTypes = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,   // <-- Not used for Set!
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE);

    // Validate parameter types
    // TODO: Right now we're ignoring the output value (param[2]).
    if (ParamTypes != ExpectedTypes) {
        DMSG("fTPM_AuthVar_Get: bad param types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // REVISIT: Validate parameters here or in GetVariable?
    SetParam = (VARIABLE_SET_PARAM *)Params[0].memref.buffer;
    SetParamSize = Params[0].memref.size;

    // TODO: Check that we're init'ed first
    
    // Call VarOps
    Status = SetVariable(SetParamSize, SetParam);

    // If there is not enough room in NV, try to reclaim it and re-run the command
    if(Status == TEE_ERROR_OUT_OF_MEMORY) {
        CompressAuthvarMemory();
        Status = SetVariable(SetParamSize, SetParam);
    }

    DMSG("Status: 0x%x", Status);

    Params[2].value.a = 0;
    Params[2].value.b = Status;

    return Status;
}

//
// Query Authenticated Variable Info
//
static TEE_Result fTPM_AuthVar_Query(
    uint32_t  ParamTypes,
    TEE_Param Params[4]
)
{
    VARIABLE_QUERY_PARAM    *QueryParam;
    VARIABLE_QUERY_RESULT   *QueryResult;
    uint32_t    QueryParamSize;
    uint32_t   *QueryResultSize;
    uint32_t    ExpectedTypes;
    TEE_Result  Status;

    DMSG("AV cmd");

    ExpectedTypes = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE);

    // Validate parameter types
    // TODO: Right now we're ignoring the output value (param[2]).
    if (ParamTypes != ExpectedTypes) {
        IMSG("fTPM_AuthVar_Get: bad param types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // REVISIT: Validate parameters here or in GetVariable?
    QueryParam = (VARIABLE_GET_NEXT_PARAM *)Params[0].memref.buffer;
    QueryParamSize = Params[0].memref.size;

    QueryResult = (VARIABLE_GET_RESULT *)Params[1].memref.buffer;
    QueryResultSize = &Params[1].memref.size;

    // TODO: Check that we're init'ed first

    // Call VarOps
    Status = QueryVariableInfo(QueryParamSize, QueryParam, QueryResultSize, QueryResult);

    // Authvars driver expects TEE_SUCCESS, TEE_ERROR_SHORT_BUFFER,
    // or TEEC_ERROR_ITEM_NOT_FOUND as a return value. All other values
    // are handled as errors. Return values are also passed  back through
    // parameter 2b to be handled by the command specific part of the driver.
    Params[2].value.b = Status;

    return Status;
}

// 
// Called when a TA is invoked. Note, paramters come from normal world.
// 
TEE_Result TA_InvokeCommandEntryPoint(void      *sess_ctx,
                                      uint32_t   cmd_id,
                                      uint32_t   param_types,
                                      TEE_Param  params[4])
{
    TEE_Result Status;

    // Unused parameter(s)
    UNREFERENCED_PARAMETER(sess_ctx);

    // Handle command invocation
    switch (cmd_id) {

        case TA_FTPM_SUBMIT_COMMAND: {
            Status = fTPM_Submit_Command(param_types, params);
            return Status;
        }

        case TA_FTPM_EMULATE_PPI: {
            Status = fTPM_Emulate_PPI(param_types, params);
            return Status;
        }

        case TA_FTPM_GET_VARIABLE: {
            Status = fTPM_AuthVar_Get(param_types, params);
            return Status;
        }

        case TA_FTPM_GET_NEXT_VARIABLE: {
            Status = fTPM_AuthVar_GetNext(param_types, params);
            return Status;
        }

        case TA_FTPM_SET_VARIABLE: {
            Status = fTPM_AuthVar_Set(param_types, params);
            return Status;
        }

        case TA_FTPM_QUERY_VARINFO: {
            Status = fTPM_AuthVar_Query(param_types, params);
            return Status;
        }

        case TA_FTPM_EXIT_BOOT_SERVICES: {
            // TODO: DO WE CARE ABOUT PARAMS HERE?
            fTPMIsRuntime = true;
            return TEE_SUCCESS;
        }

        default: {
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
}