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

#pragma once
#include <varops.h>

VOID
SearchList(
    PCUNICODE_STRING     UnicodeName,
    PCGUID               VendorGuid,
    PUEFI_VARIABLE      *Var,
    VARTYPE             *VarType
);

TEE_Result
CreateVariable(
    PCUNICODE_STRING        UnicodeName,
    PCGUID                  VendorGuid,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtAttributes,
    UINT32                  DataSize,
    PBYTE                   Data
);

TEE_Result
DeleteVariable(
    PUEFI_VARIABLE  Var,
    VARTYPE         VarType,
    ATTRIBUTES      Attributes
);

TEE_Result
AppendVariable(
    PUEFI_VARIABLE          Var,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtAttributes,
    PBYTE                   Data,
    UINT32                  DataSize
);

TEE_Result
ReplaceVariable(
    PUEFI_VARIABLE          Var,
    ATTRIBUTES              Attributes,
    PEXTENDED_ATTRIBUTES    ExtendedAttributes,
    PBYTE                   Data,
    UINT32                  DataSize
);

VOID
QueryByAttribute(
    ATTRIBUTES  Attributes,
    PUINT64     VarStorageMax,
    PUINT64     VarStorageRemaining,
    PUINT64     MaxVarSize
);