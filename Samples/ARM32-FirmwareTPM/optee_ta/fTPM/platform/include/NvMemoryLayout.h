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

#ifndef _COMBINEDNVMEMORY_H
#define _COMBINEDNVMEMORY_H

#include <PlatformData.h>
#define ROUNDUP(x, y)			((((x) + (y) - 1) / (y)) * (y))

//
// Overall size of NV, not just the TPM's NV storage (128K!)
//
// A change to this constant should be the result of a change to
// implementation.h, Admin.h, and/or varops.h. A change to the size
// of fTPM's NV memory needs to be consistent accross these headers.
#define NV_TOTAL_MEMORY_SIZE	(0x20000UL)
#define NV_BLOCK_SIZE           (0x1000UL)

// Actual size of Admin space used. (See note in NVMem.c)
#define TPM_STATE_SIZE          0x10

// Admin space tacked on to NV, padded out to NV_BLOCK_SIZE alignment.
#define NV_TPM_STATE_SIZE       ROUNDUP(TPM_STATE_SIZE, NV_BLOCK_SIZE)
#define NV_TPM_STORAGE_SIZE     ROUNDUP(NV_MEMORY_SIZE, NV_BLOCK_SIZE)



// Total allocation of the fTPM TA's storage for Authenticated Variables
//      fTPM TA storage (128K total):
//                        16K   (0x4000  bytes) - TPM NV storage
//                         1k   (0x1000   bytes) - fTPM "Admin" state
//          128K - (16K + 1k)   (0x1B000 bytes) - AuthVar storage
#define NV_AUTHVAR_SIZE     (NV_TOTAL_MEMORY_SIZE - (NV_TPM_STORAGE_SIZE + NV_TPM_STATE_SIZE))
#define NV_AUTHVAR_START    (NV_TOTAL_MEMORY_SIZE - NV_AUTHVAR_SIZE)

//
// OpTEE still has an all or nothing approach to reads/writes. To provide
// more performant access to storage, break up NV accross 1Kbyte blocks.
//
// Note that NV_TOTAL_MEMORY_SIZE *MUST* be a factor of NV_BLOCK_SIZE.
//

#define NV_BLOCK_COUNT      ((NV_TOTAL_MEMORY_SIZE) / (NV_BLOCK_SIZE))

//
// This offset puts the revision field at the end of the TPM Admin
// state. The Admin space in NV is down to ~16 bytes but is padded out to
// 1k bytes to avoid alignment issues and allow for growth.
//
//TODO: don't use sizeof(uint32)
#define NV_CHIP_REVISION_OFFSET ( (NV_MEMORY_SIZE) + (NV_TPM_STATE_SIZE) - (2 * sizeof(UINT32)) )


#endif