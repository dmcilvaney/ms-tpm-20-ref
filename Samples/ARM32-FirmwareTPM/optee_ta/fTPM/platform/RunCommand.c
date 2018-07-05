/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

//**Introduction
// This module provides the platform specific entry and fail processing. The
// _plat__RunCommand() function is used to call to ExecuteCommand() in the TPM code.
// This function does whatever processing is necessary to set up the platform 
// in anticipation of the call to the TPM including settup for error processing.
//
// The _plat__Fail() function is called when there is a failure in the TPM. The TPM
// code will have set the flag to indicate that the TPM is in failure mode.
// This call will then recursively call ExecuteCommand in order to build the
// failure mode response. When ExecuteCommand() returns to _plat__Fail(), the
// platform will do some platform specif operation to return to the environment in
// which the TPM is executing. For a simulator, setjmp/longjmp is used. For an OS,
// a system exit to the OS would be appropriate.

//** Includes and locals
#include "PlatformData.h"
#include "Platform_fp.h"
#include <setjmp.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

jmp_buf              s_jumpBuffer;

//** Functions

//***_plat__RunCommand()
// This version of RunCommand will set up a jum_buf and call ExecuteCommand(). If
// the command executes without failing, it will return and RunCommand will return.
// If there is a failure in the command, then _plat__Fail() is called and it will 
// longjump back to RunCommand which will call ExecuteCommand again. However, this
// time, the TPM will be in failure mode so ExecuteCommand will simply build
// a failure response and return.
LIB_EXPORT void
_plat__RunCommand(
    uint32_t         requestSize,   // IN: command buffer size
    unsigned char   *request,       // IN: command buffer
    uint32_t        *responseSize,  // IN/OUT: response buffer size
    unsigned char   **response      // IN/OUT: response buffer
    )
{
    setjmp(s_jumpBuffer);
    ExecuteCommand(requestSize, request, responseSize, response);
}
    

//***_plat__Fail()
// This is the platform depended failure exit for the TPM.
LIB_EXPORT NORETURN void
_plat__Fail(void)
{
    TEE_Panic(TEE_ERROR_BAD_STATE);
}