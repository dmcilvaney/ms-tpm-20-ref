/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

//** Description
// This file will instance the TPM variables that are not stack allocated. The
// descriptions for these variables are in Global.h for this project.

//** Includes
#include    "Implementation.h"
#include    "PlatformData.h"

// From Cancel.c
BOOL                 s_isCanceled;

// From Clock.c
unsigned int         s_adjustRate;
BOOL                 s_timerReset;
BOOL                 s_timerStopped;

#ifndef HARDWARE_CLOCK
clock64_t            s_realTimePrevious;
clock64_t            s_tpmTime;

clock64_t            s_lastSystemTime;
clock64_t            s_lastReportedTime;


#endif


// From LocalityPlat.c
unsigned char        s_locality;

// From Power.c
BOOL                 s_powerLost;

// From Entropy.c
// This values is used to determine if the entropy generator is broken. If two 
// consecutive values are the same, then the entropy generator is considered to be
// broken.
uint32_t             lastEntropy;


// From NVMem.c
#ifdef  VTPM
#   undef FILE_BACKED_NV
#endif
#ifdef FILE_BACKED_NV
FILE                *s_NVFile = NULL;
#endif
unsigned char        s_NV[NV_MEMORY_SIZE];
BOOL                 s_NvIsAvailable;
BOOL                 s_NV_unrecoverable;
BOOL                 s_NV_recoverable;

// From PPPlat.c
BOOL  s_physicalPresence;