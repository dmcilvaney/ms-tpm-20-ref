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

#include <varauth.h>

 // Track PK set/unset 
bool SecureBootInUserMode = FALSE;

// Usage for #def'ed GUIDs
static CONST GUID EfiCertX509Guid = EFI_CERT_X509_GUID;
static CONST GUID EfiCertTypePKCS7Guid = EFI_CERT_TYPE_PKCS7_GUID;

// Selector for cert parsing (parse all or x509 only)
typedef enum _PARSE_SECURE_BOOT_OP {
    ParseAllSignature = 0,
    ParseForX509Certs,
} PARSE_SECURE_BOOT_OP;

// Storage for secureboot variable information
CONST SECUREBOOT_VARIABLE_INFO SecurebootVariableInfo[] =
{
    {
        SecureBootVariablePK,                                     // Id
        {                                                         
            sizeof(EFI_PLATFORMKEY_VARIABLE) - sizeof(WCHAR),     // UnicodeName.Length
            sizeof(EFI_PLATFORMKEY_VARIABLE),                     // UnicodeName.MaximumLength
            (CONST PWCH) EFI_PLATFORMKEY_VARIABLE,                // UnicodeName.Buffer
        },                                                        
        EFI_GLOBAL_VARIABLE,                                      // VendorGuid
    },                                                            
    {                                                             
        SecureBootVariableKEK,                                    // Id
        {                                                         
            sizeof(EFI_KEK_SECURITY_DATABASE) - sizeof(WCHAR),    // UnicodeName.Length
            sizeof(EFI_KEK_SECURITY_DATABASE),                    // UnicodeName.MaximumLength
            (CONST PWCH) EFI_KEK_SECURITY_DATABASE,               // UnicodeName.Buffer
        },                                                        
        EFI_GLOBAL_VARIABLE,                                      // VendorGuid
    },
    {
        SecureBootVariableDB,                                     // Id
        {                                                         
            sizeof(EFI_IMAGE_SECURITY_DATABASE) - sizeof(WCHAR),  // UnicodeName.Length
            sizeof(EFI_IMAGE_SECURITY_DATABASE),                  // UnicodeName.MaximumLength
            (CONST PWCH) EFI_IMAGE_SECURITY_DATABASE,             // UnicodeName.Buffer
        },                                                        
        EFI_IMAGE_SECURITY_DATABASE_GUID,                         // VendorGuid
    },
    {
        SecureBootVariableDBX,                                    // Id
        {
            sizeof(EFI_IMAGE_SECURITY_DATABASE1) - sizeof(WCHAR), // UnicodeName.Length
            sizeof(EFI_IMAGE_SECURITY_DATABASE1),                 // UnicodeName.MaximumLength
            (CONST PWCH) EFI_IMAGE_SECURITY_DATABASE1,            // UnicodeName.Buffer
        },
        EFI_IMAGE_SECURITY_DATABASE_GUID,                         // VendorGuid
    },
};

//
// Auth functions
//

// TODO:
// ParseAuthenticationParams
// IdentifySecurebootVariable
// AuthenticateSecurebootVariableAccess
//      PopulateCerts
//          ReadSecurebootVariables
//      Pkcs7Verify
//      Pkcs7GetSigners
// CheckForDuplicateSignatures
//      GetNonVolatileVariableOnly
//      ParseSecurebootVariables
//      CheckSignatureListSanity

TEE_Result
AuthenticateSetVariable(
    PCUNICODE_STRING         UnicodeName,
    PGUID                    VendorGuid,
    PCUEFI_VARIABLE          Var,
    ATTRIBUTES               Attributes,
    PBYTE                    Data,
    UINT32                   DataSize,
    PEXTENDED_ATTRIBUTES     ExtendedAttributes,
    PBOOLEAN                 DuplicateFound,
    PBYTE                   *Content,
    PUINT32                  ContentSize
)
/*++

    Routine Description:

        Function for authenticating a variable based on EFI_VARIABLE_AUTHENTICATION_2.
        This is time based authentication

    Arguments:

        UnicodeName - Name of variable

        VendorGuid - GUID of the variable

        Var - Pointer to in-memory representation of the variable

        Attributes - UEFI variable attributes

        Data - supplies data (Serialization of Authentication structure and variable's content)

        DataSize - Size in bytes of Data

        ExtendedAttributes - Optional attributes for authenticated variables

        DuplicateFound - TRUE if duplicates are found in the content being appended to the existing content

        Content - If duplicates are found in the content being appended to the existing content,
        the redundant signatures are stripped and this field points to that reduced content
        (Memory is allocated within this method and should be freed by caller)

        ContentSize - Size in bytes of Content

    Returns:

        TEE_Result

--*/
{
    *DuplicateFound = FALSE;
    return TEE_SUCCESS;
}