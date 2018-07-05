/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

//**Introduction
/*
    This module simulates the cancel pins on the TPM.
*/
//** Includes, Typedefs, Structures, and Defines
#include "PlatformData.h"
#include "Platform_fp.h"

//** Functions

LIB_EXPORT int
_plat__IsCanceled(
    void
    )
{
    // return cancel flag
    return s_isCanceled;
}

//***_plat__SetCancel()

// Set cancel flag.
LIB_EXPORT void
_plat__SetCancel(
    void
    )
{
    s_isCanceled = TRUE;
    return;
}

//***_plat__ClearCancel()
// Clear cancel flag
LIB_EXPORT void
_plat__ClearCancel(
    void
    )
{
    s_isCanceled = FALSE;
    return;
}