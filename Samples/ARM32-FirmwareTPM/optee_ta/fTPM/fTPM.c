/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

#define STR_TRACE_USER_TA "fTPM"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include "fTPM.h"

#define TA_ALL_PARAM_TYPE(type) TEE_PARAM_TYPES(type, type, type, type)

//
// Ensure we have only one active session
//
static bool fTPMSessionActive = false;

//
// Initialization
//
bool fTPMInitialized = false;

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

#ifdef fTPMDebug
    DMSG("Entry Point\n");
#endif

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

#ifdef fTPMDebug
    DMSG("NVEnable Complete\n");
#endif

    // This only occurs when there is no previous NV state, i.e., on first
    // boot, after recovering from data loss, we reset the platform, etc.
    if (_plat__NvNeedsManufacture()) {
#ifdef fTPMDebug
        DMSG("TPM_Manufacture\n");
#endif
        TPM_Manufacture(1);
    }

    // "Power-On" the platform
    _plat__Signal_PowerOn();

    // Internal init for reference implementation
    _TPM_Init();

#ifdef fTPMDebug
    DMSG("Init Complete\n");
#endif

    // Startup with state
    if (g_chipFlags.fields.TpmStatePresent) {

        // Re-use request buffer for response (ignored)
        respBuf = startupState;
        respLen = STARTUP_SIZE;

        ExecuteCommand(STARTUP_SIZE, startupState, &respLen, &respBuf);
        if (fTPMResponseCode(respLen, respBuf) == TPM_RC_SUCCESS) {
            goto Exit;
        }

#ifdef fTPMDebug
        DMSG("Fall through to startup clear\n");
#endif

        goto Clear;
    }

#ifdef fTPMDebug
    DMSG("No TPM state present\n");
#endif

Clear:
    // Re-use request buffer for response (ignored)
    respBuf = startupClear;
    respLen = STARTUP_SIZE;

    // Fall back to a Startup Clear
    ExecuteCommand(STARTUP_SIZE, startupClear, &respLen, &respBuf);

Exit:
    // Init is complete, indicate so in fTPM admin state.
    g_chipFlags.fields.TpmStatePresent = 1;
    _admin__SaveChipFlags();

    // Initialization complete
    fTPMInitialized = true;

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

    // Unreferenced parameters
    UNREFERENCED_PARAMETER(params);
    UNREFERENCED_PARAMETER(sess_ctx);

    // Validate parameter types
    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Only one active session to the fTPM is permitted
    if (fTPMSessionActive) {
        return TEE_ERROR_ACCESS_CONFLICT;
    }

    // Active session
    fTPMSessionActive = true;

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
    if (fTPMSessionActive) {
        fTPMSessionActive = false;
    }
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
// Called when a TA is invoked. Note, paramters come from normal world.
// 
TEE_Result TA_InvokeCommandEntryPoint(void      *sess_ctx,
                                      uint32_t  cmd_id,
                                      uint32_t  param_types,
                                      TEE_Param params[4])
{
    // Unused parameter(s)
    UNREFERENCED_PARAMETER(sess_ctx);

    // Handle command invocation
    switch (cmd_id) {

        case TA_FTPM_SUBMIT_COMMAND: {
            return fTPM_Submit_Command(param_types, params);
        }

        case TA_FTPM_EMULATE_PPI: {
            return fTPM_Emulate_PPI(param_types, params);
        }

        default: {
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
}