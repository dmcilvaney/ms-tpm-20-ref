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
#include <varmgmt.h>

 // Track PK set/unset 
bool SecureBootInUserMode = FALSE;

// Usage for #def'ed GUIDs
static CONST GUID EfiCertX509Guid = EFI_CERT_X509_GUID;
static CONST GUID EfiCertTypePKCS7Guid = EFI_CERT_TYPE_PKCS7_GUID;

// Selector for cert parsing (parse all or x509 only)
typedef enum _PARSE_SECURE_BOOT_OP {
    ParseOpAll = 0,
    ParseOpX509,
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
// Prototypes
//

static
TEE_Result
ValidateParameters(
    PBYTE        Data,              // IN
    UINT32       DataSize,          // IN
    PBYTE       *SignedData,        // OUT
    UINT32      *SignedDataSize,    // OUT
    PBYTE       *ActualData,        // OUT
    UINT32      *ActualDataSize,    // OUT
    EFI_TIME    *EfiTime            // OUT
);

static
TEE_Result
SecureBootVarAuth(
    SECUREBOOT_VARIABLE Id,         // IN
    PBYTE AuthenticationData,       // IN
    UINT32 AuthenticationDataSize,  // IN
    PBYTE Data,                     // IN
    UINT32 DataSize,                // IN
    PBYTE DataToVerify,             // IN
    UINT32 DataToVerifySize         // IN
);

static
TEE_Result
CheckSignatureList(
    EFI_SIGNATURE_LIST* SignatureList,
    PBYTE SignatureListEnd,
    PUINT32 NumberOfEntries
);

static
TEE_Result
VerifyTime(
    EFI_TIME    *FirstTime,
    EFI_TIME    *SecondTime
);

static
BOOLEAN
IsBefore(
    EFI_TIME    *FirstTime,
    EFI_TIME    *SecondTime
);

static
BOOLEAN
IdentifySecurebootVariable(
    PCWSTR VariableName,        // IN
    PCGUID VendorGuid,          // IN
    PSECUREBOOT_VARIABLE Id     // OUT
);

//
// Auth functions
//

static
BOOLEAN
WrapPkcs7Data(
    CONST UINT8  *P7Data,           // IN
    UINTN        P7Length,          // IN
    BOOLEAN      *WrapFlag,         // OUT
    UINT8        **WrapData,        // OUT
    UINTN        *WrapDataSize      // OUT
)
/*++
    Routine Descrition:

        Check input P7Data is a wrapped ContentInfo structure or not. If not,
        construct a new structure to wrap P7Data.

        Caution: This function may receive untrusted input. UEFI Authenticated
        Variable is external input, so this function will do basic check for
        PKCS#7 data structure.

    Arguments:

        P7Data - Pointer to the PKCS#7 message to verify.

        P7Length - Length of the PKCS#7 message in bytes.

        WrapFlag - Receives TRUE if P7Data is ContentInfo structure.

        WrapData - If return status of this function is TRUE:
                     1) WrapData = pointer to P7Data, if WrapFlag == TRUE
                     2) WrapData = to a new ContentInfo structure, otherwise.
                        It is the caller's responsibility to free this buffer.

        WrapDataSize - Length of structure pointed to by WrapData in bytes.

    Returns:

        TRUE    The operation is finished successfully.

        FALSE   The operation is failed due to lack of resources.

--*/

{
    UINT8 mOidValue[9] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };
    UINT8 *signedData;
    BOOLEAN wrapped = FALSE;

    // Determine whether input P7Data is a wrapped ContentInfo structure
    if ((P7Data[4] == 0x06) && (P7Data[5] == 0x09))
    {
        if (memcmp(P7Data + 6, mOidValue, sizeof(mOidValue)) == 0)
        {
            if ((P7Data[15] == 0xA0) && (P7Data[16] == 0x82))
            {
                wrapped = TRUE;
            }
        }
    }

    // If already wrapped then update outputs and return.
    if (wrapped)
    {
        *WrapData = (UINT8 *)P7Data;
        *WrapDataSize = P7Length;
        *WrapFlag = wrapped;
        return TRUE;
    }

    // Wrap PKCS#7 signeddata to a ContentInfo structure
    *WrapDataSize = P7Length + 19;
    *WrapData = TEE_Malloc(*WrapDataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO);
    if (*WrapData == NULL)
    {
        // Unable to alloc buffer
        *WrapFlag = wrapped;
        return FALSE;
    }

    signedData = *WrapData;

    //
    // Part1: 0x30, 0x82.
    //
    signedData[0] = 0x30;
    signedData[1] = 0x82;

    //
    // Part2: Length1 = P7Length + 19 - 4, in big endian.
    //
    signedData[2] = (UINT8)(((UINT16)(*WrapDataSize - 4)) >> 8);
    signedData[3] = (UINT8)(((UINT16)(*WrapDataSize - 4)) & 0xff);

    //
    // Part3: 0x06, 0x09.
    //
    signedData[4] = 0x06;
    signedData[5] = 0x09;

    //
    // Part4: OID value -- 0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x07 0x02.
    //
    memcpy(signedData + 6, mOidValue, sizeof(mOidValue));

    //
    // Part5: 0xA0, 0x82.
    //
    signedData[15] = 0xA0;
    signedData[16] = 0x82;

    //
    // Part6: Length2 = P7Length, in big endian.
    //
    signedData[17] = (UINT8)(((UINT16)P7Length) >> 8);
    signedData[18] = (UINT8)(((UINT16)P7Length) & 0xff);

    //
    // Part7: P7Data.
    //
    memcpy(signedData + 19, P7Data, P7Length);

    *WrapFlag = wrapped;
    return TRUE;
}

static
BOOLEAN
Pkcs7GetSigners(
    CONST UINT8  *P7Data,
    UINTN        P7Length,
    UINT8        **CertStack,
    UINTN        *StackLength,
    UINT8        **TrustedCert,
    UINTN        *CertLength
)
{
    // TODO
    return FALSE;
}

static
BOOLEAN
Pkcs7Verify(
    CONST UINT8  *P7Data,
    UINTN        P7Length,
    CONST UINT8  *TrustedCert,
    UINTN        CertLength,
    CONST UINT8  *InData,
    UINTN        DataLength
)
/*++

    Routine Description:

        Verifies the validility of a PKCS#7 signed data as described in
        "PKCS #7: Cryptographic Message Syntax Standard". The input
        signed data could be wrapped in a ContentInfo structure.

        If P7Data, TrustedCert or InData is NULL, then return FALSE.
        If P7Length, CertLength or DataLength overflow, then return FAlSE.

        Caution: This function may receive untrusted input. UEFI Authenticated
        Variable is external input, so this function will do basic check for
        PKCS#7 data structure.

    Arguments:

        P7Data - Pointer to the PKCS#7 message to verify.

        P7Length - Length of the PKCS#7 message in bytes.

        TrustedCert - Pointer to a trusted/root certificate encoded in DER,
                      which is used for certificate chain verification.

        CertLength - Length of the trusted certificate in bytes.

        InData - Pointer to the content to be verified.

        DataLength - Length of InData in bytes.

    Returns:

        TRUE - The specified PKCS#7 signed data is valid.

        FALSE - Invalid PKCS#7 signed data.

--*/
{
    UINT8 *signedData = NULL;
    UINTN signedDataSize = 0;
    BOOLEAN wrapped = FALSE;
    BOOLEAN retVal = FALSE;

    // Check input parameters.
    if ((P7Data == NULL) || (TrustedCert == NULL) || (InData == NULL) ||
        (P7Length > INT_MAX) || (CertLength > INT_MAX) || (DataLength > INT_MAX)) {
        return FALSE;
    }

    // Wrap PKCS7 data, if necessary
    if (!WrapPkcs7Data(P7Data, P7Length, &wrapped, &signedData, &signedDataSize))
    {
        retVal = FALSE;
        goto Cleanup;
    }

    // TODO:
    // 1. Populate PKCS7 Structure (d2i_PKCS7())
    // 2. Make sure it's signed (no validation yet)
    // 3. Get certs together
    // 4. Verify the PKCS#7 signedData structure

    extern UINT16 CryptHashStart(
        PHASH_STATE      hashState,     // OUT: the running hash state
        TPM_ALG_ID       hashAlg        // IN: hash algorithm
    );

Cleanup:
    if (!wrapped)
    {
        TEE_Free(signedData);
    }

    return retVal;
}

static
TEE_Result
ParseSecurebootVariables(
    PBYTE Data,                 // IN
    UINT32 DataSize,            // IN
    PARSE_SECURE_BOOT_OP Op,    // IN
    PDATA_BLOB Certs,           // INOUT
    PUINT32 NumberOfCerts       // INOUT
)
/*++

    Routine Description:

        Function used to parse a retrieved secureboot variable

    Arguments:

        Data - Content of an authenticated secureboot variable

        DataSize - Size in bytes of Data

        Op - Opcode to choose between parsing all certs or only x509 certs

        Certs - If NULL, NumberOfCerts contains total number of certs in variable filtered by Op
                If non-NULL, Certs contains a list of certificates

        NumberOfCerts - contains total number of certs in variable filtered by Op

    Returns:

        TEE_Result

--*/
{
    UINT32 numberOfCerts = 0, index = 0, i, numberOfEntries, certSize = 0;
    PBYTE locationInSigLists, locationEnd, certEntry, firstCert = NULL;
    EFI_SIGNATURE_LIST* signatureList;
    TEE_Result status;
    BOOLEAN alloc = FALSE;

    locationInSigLists = Data;
    locationEnd = Data + DataSize;

    if (DataSize < sizeof(EFI_SIGNATURE_LIST))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }
    
    // Integer overflow check
    if ((UINT32)locationEnd <= (UINT32)Data)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    while (locationInSigLists < locationEnd)
    {
        alloc = FALSE;
        signatureList = (EFI_SIGNATURE_LIST*)locationInSigLists;

        status = CheckSignatureList(signatureList, locationEnd, &numberOfEntries);
        if (status != TEE_SUCCESS)
        {
            goto Cleanup;
        }

        if (Op == ParseOpAll)
        {
            numberOfCerts += numberOfEntries;
            certSize = signatureList->SignatureSize;
            firstCert = (PBYTE)signatureList + sizeof(EFI_SIGNATURE_LIST);
            alloc = TRUE;
        }
        else
        {
            if ((Op == ParseOpX509) && (memcmp(&signatureList->SignatureType, &EfiCertX509Guid, sizeof(GUID)) == 0))
            {
                numberOfCerts += numberOfEntries;
                certSize = signatureList->SignatureSize - sizeof(EFI_SIGNATURE_DATA);
                firstCert = (PBYTE)signatureList + sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA);
                alloc = TRUE;
            }
        }

        if (alloc)
        {
            if (Certs != NULL)
            {
                for (i = 0; i < numberOfEntries; i++)
                {
                    // TODO: Should be assert
                    if (firstCert == NULL)
                    {
                        status = TEE_ERROR_BAD_PARAMETERS;
                        goto Cleanup;
                    }

                    certEntry = firstCert + (i * signatureList->SignatureSize);

                    if (index >= *NumberOfCerts)
                    {
                        status = TEE_ERROR_BAD_PARAMETERS;
                        goto Cleanup;
                    }

                    Certs[index].DataSize = certSize;

                    //if (!(Certs[index].Data = TREE_Malloc(certSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
                    //{
                    //    status = TEE_ERROR_OUT_OF_MEMORY;
                    //    goto Cleanup;
                    //}
                    //
                    //memmove(Certs[index].Data, certEntry, certSize);

                    index++;
                }
            }
        }

        locationInSigLists += signatureList->SignatureListSize;
    }

    if (locationInSigLists != locationEnd)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    *NumberOfCerts = numberOfCerts;

Cleanup:
    if (status != TEE_SUCCESS)
    {
        for (i = 0; (i < index) && (i < *NumberOfCerts); i++)
        {
            TEE_Free(Certs[i].Data);
        }
    }

    return status;
}

TEE_Result
ReadSecurebootVariables(
    SECUREBOOT_VARIABLE Id,     // IN
    BYTE** Data,                // OUT
    PUINT32 DataSize            // OUT
)
/*++

    Routine Description:

        This function reads a secureboot authenticated variable

    Arguments:

        Id - Enum selecting secureboot variable

        Data - Content of the variable

        DataSize - Size in bytes of the variable

    Returns:

        Status Code

--*/
{
    SIZE_T dataSize;
    PBYTE data = NULL;
    PUEFI_VARIABLE var = NULL;
    TEE_Result status;
    VARTYPE variableType;

    // Read the data from non volatile storage.
    SearchList(&SecurebootVariableInfo[Id].UnicodeName,
               &SecurebootVariableInfo[Id].VendorGuid,
               &var, &variableType);

    if (!var)
    {
        status = TEE_ERROR_ITEM_NOT_FOUND;
        goto Cleanup;
    }

    if (!(data = TEE_Malloc(var->DataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
    {
        status = TEE_ERROR_OUT_OF_MEMORY;
        goto Cleanup;
    }

    status = RetrieveVariable(var, data, &var->DataSize, &dataSize);
    if ((status != TEE_SUCCESS) || (dataSize != var->DataSize))
    {
        goto Cleanup;
    }

    // Sanity check returned data size
    if ((UINT32)dataSize != (var->DataSize))
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Pass along pointer to secure boot variable
    *Data = data;
    *DataSize = var->DataSize;

Cleanup:
    if((status != TEE_SUCCESS) && (data))
    {
        TEE_Free(data);
    }
    return status;
}

static
TEE_Result
PopulateCerts(
    SECUREBOOT_VARIABLE Var1,
    SECUREBOOT_VARIABLE Var2,
    PDATA_BLOB *Certs,
    PUINT32 NumberOfCerts
)
/*++

    Routine Description:

        Function to read and populate X509 certs from secureboot variables

    Arguments:

        Var1 - Enum selecting secureboot variable

        Var1 - Enum selecting secureboot variable

        Certs - Supplies a list of certificates parsed from both the variables

        NumberOfCerts - supplies number of certs in Certs

    Returns:

        Status Code

--*/
{
    UINT32 count1 = 0, count2 = 0, i, parsedCount, data1Size = 0, data2Size = 0;
    PDATA_BLOB certs = NULL;
    PBYTE data1 = NULL, data2 = NULL;
    TEE_Result status;
    BOOLEAN doBoth = FALSE;

    // We assume we have a Var1 (otherwise why were we called) but Var2 is optional
    if (Var2 != SecureBootVariableEnd)
    {
        doBoth = TRUE;
    }

    // Read the variable(s)
    status = ReadSecurebootVariables(Var1, &data1, &data1Size);
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }

    // Find how many certs qualify and allocate memory for the list accordingly
    status = ParseSecurebootVariables(data1, data1Size, ParseOpX509, NULL, &count1);
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }

    if (doBoth)
    {
        // Read the variable(s)
        status = ReadSecurebootVariables(Var2, &data2, &data2Size);
        if (status != TEE_SUCCESS)
        {
            goto Cleanup;
        }

        // Find how many certs qualify and allocate memory for the list accordingly
        status = ParseSecurebootVariables(data2, data2Size, ParseOpX509, NULL, &count2);
        if (status != TEE_SUCCESS)
        {
            goto Cleanup;
        }
    }

    certs = TEE_Malloc((sizeof(DATA_BLOB) * (count1 + count2)), 0);
    if (!certs)
    {
        status = TEE_ERROR_OUT_OF_MEMORY;
        goto Cleanup;
    }

    parsedCount = count1;

    status = ParseSecurebootVariables(data1, data1Size, ParseOpX509, certs, &parsedCount);
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }

    // TODO: Should be assert
    if (parsedCount != count1)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    if (doBoth)
    {
        parsedCount = count2;

        status = ParseSecurebootVariables(data2, data2Size, ParseOpX509, &certs[count1], &parsedCount);
        if (status != TEE_SUCCESS)
        {
            goto Cleanup;
        }

        // TODO: Should be assert
        if (parsedCount != count2)
        {
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }
    }

    *Certs = certs;
    *NumberOfCerts = count1 + count2;

Cleanup:
    TEE_Free(data1);
    TEE_Free(data2);

    if (status != TEE_SUCCESS)
    {
        for (i = 0; i < (count1 + count2); i++)
        {
            TEE_Free(certs[i].Data);
        }
        TEE_Free(certs);
    }

    return status;
}

static
TEE_Result
CheckSignatureList(
    EFI_SIGNATURE_LIST* SignatureList,
    PBYTE SignatureListEnd,
    PUINT32 NumberOfEntries
)
/*++

    Routine Description:

        Function to check the correctness of EFI Signature Lists

    Arguments:

        SignatureList - Pointer to a single EFI signature list

        SignatureListEnd - End of list

        NumberOfEntries - Total number of signatures in this list

    Returns:

        Status Code

--*/
{
    TEE_Result status;
    UINT32 count;

    // Sanity checks on the signature list
    if (((SignatureListEnd - (PBYTE)SignatureList) < (int) sizeof(EFI_SIGNATURE_LIST))
        || (((PBYTE)SignatureList + SignatureList->SignatureListSize) < (PBYTE)SignatureList)
        || (((PBYTE)SignatureList + SignatureList->SignatureListSize) > SignatureListEnd))
    {
        DMSG("FAILED0");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    if ((SignatureList->SignatureListSize == 0)
        || (SignatureList->SignatureListSize < sizeof(EFI_SIGNATURE_LIST)))
    {
        DMSG("FAILED1");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    count = SignatureList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST);

    if (count == 0 || count % SignatureList->SignatureSize)
    {
        DMSG("FAILED2");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    if (SignatureList->SignatureHeaderSize != 0)
    {
        DMSG("FAILED3");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    *NumberOfEntries = (SignatureList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST)) /
        SignatureList->SignatureSize;

Cleanup:
    return status;
}

static
TEE_Result
CheckForDuplicateSignatures(
    PCUEFI_VARIABLE Var,
    PBYTE Data,
    UINT32 DataSize,
    PBOOLEAN DuplicatesFound,
    BYTE** NewData,
    PUINT32 NewDataSize
)
/*++

    Routine Description:

        Function to check for duplicates while appending db/dbx.

        Per UEFI 2.3.1, duplicate signatures to be stripped from data before appending existing content

    Arguments:

        Var - A pointer to an inmemory representation of the variable

        Data - Data being appended to Var

        DataSize - Size in bytes of Data

        DuplicatesFound - TRUE if duplicates were found in Data

        NewData - supplies a pointer containing data after redundant signatures are removed

        NewDataSize - Size in bytes of NewData

    Returns:

        Status Code

--*/
{
    PBYTE data, newData = NULL, nextCert, locationInSigLists, locationEnd, certEntry;
    SIZE_T dataSize;
    PDATA_BLOB existingCerts = NULL;
    UINT32 existingNumberOfCerts, newDataSize = 0, certSize, numberOfEntries, i, j;
    EFI_SIGNATURE_LIST* signatureList;
    TEE_Result status;
    BOOLEAN duplicatesFound = FALSE;

    // First, read the variable from non volatile storage.
    if (!(data = TEE_Malloc(Var->DataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
    {
        DMSG("FAILED: Malloc");
        status = TEE_ERROR_OUT_OF_MEMORY;
        goto Cleanup;
    }

    status = RetrieveVariable(Var, data, Var->DataSize, &dataSize);
    if ((status != TEE_SUCCESS) || ((UINT32)dataSize != (Var->DataSize)))
    {
        DMSG("FAILED: RetrieveVariable");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    status = ParseSecurebootVariables(data, Var->DataSize, ParseOpAll, NULL, &existingNumberOfCerts);
    if ((status != TEE_SUCCESS) || (existingNumberOfCerts == 0))
    {
        DMSG("FAILED: ParseSecurebootVariables");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    existingCerts = TEE_Malloc(existingNumberOfCerts * sizeof(DATA_BLOB), TEE_USER_MEM_HINT_NO_FILL_ZERO);
    if (!existingCerts)
    {
        DMSG("FAILED: Malloc2");
        status = TEE_ERROR_OUT_OF_MEMORY;
        goto Cleanup;
    }

    status = ParseSecurebootVariables(data, Var->DataSize, ParseOpAll, existingCerts, &existingNumberOfCerts);
    if (status != TEE_SUCCESS)
    {
        DMSG("FAILED: ParseSecurebootVariables");
        goto Cleanup;
    }

    // Parse certificates from the signature lists in Data
    newDataSize = DataSize;

    newData = TEE_Malloc(newDataSize, TEE_USER_MEM_HINT_NO_FILL_ZERO);

    memmove(newData, Data, newDataSize);

    locationInSigLists = newData;
    locationEnd = newData + newDataSize;

    while (locationInSigLists < locationEnd)
    {

        signatureList = (EFI_SIGNATURE_LIST*)locationInSigLists;

        status = CheckSignatureList(signatureList, locationEnd, &numberOfEntries);
        if (status != TEE_SUCCESS)
        {
            goto Cleanup;
        }

        certSize = signatureList->SignatureSize;

        for (i = 0; i < numberOfEntries; i++)
        {
            certEntry = (PBYTE)signatureList + sizeof(EFI_SIGNATURE_LIST) + (i * signatureList->SignatureSize);


            // Check if this is present in the existing certificates
            for (j = 0; j < existingNumberOfCerts; j++)
            {

                if ((certSize == existingCerts[j].DataSize) && (memcmp(certEntry, existingCerts[j].Data, certSize) == 0))
                {
                    duplicatesFound = TRUE;

                    // Remove this from this Signature list and reduce its size
                    // Update locationEnd too
                    nextCert = certEntry + certSize;

                    // All certs ahead are brought ahead by one location, and the size is updated.
                    memmove(certEntry, nextCert, (locationEnd - nextCert));

                    // Current sig list size is reduced.
                    // Also the overall size of the aggregated list also reduces.
                    locationEnd -= certSize;
                    signatureList->SignatureListSize -= certSize;
                    newDataSize -= certSize;

                    numberOfEntries--;
                    i--;
                    break;
                }
            }
        }

        locationInSigLists += signatureList->SignatureListSize;
    }

    if (locationInSigLists != locationEnd)
    {
        DMSG("FAILED %x (locationInSigLists)!= %x (locationEnd)", locationInSigLists, locationEnd);
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    //
    // If the list is not changing, then we can safely use the already existing content.
    // If duplicates were found, it is necessary to pass this new buffer so that the input buffer is unchanged.
    // This new buffer is freed after writing to non volatile storage.
    //

    if (!duplicatesFound)
    {
        TEE_Free(newData);
        newData = NULL;
        newDataSize = 0;
    }

    *NewData = newData;
    *NewDataSize = newDataSize;
    *DuplicatesFound = duplicatesFound;

Cleanup:
    TEE_Free(data);

    return status;
}

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
    EFI_TIME efiTime, *prevEfiTime;
    PEXTENDED_ATTRIBUTES pExtAttrib;
    PBYTE data = NULL, signedData = NULL, dataToVerify = NULL, newData = NULL;
    UINT32 dataSize, signedDataSize, dataToVerifySize, newDataSize, index;
    SECUREBOOT_VARIABLE id;
    TEE_Result status = TEE_ERROR_ACCESS_DENIED;
    BOOLEAN duplicatesFound = FALSE;
    BOOLEAN isDeleteOperation = FALSE;

    DMSG("authset: DataSize: %x", DataSize);
    DMSG("authset: Data: %x", Data);

    // Is this a delete operation?
    if (!DataSize)
    {
        if (!Var)
        {
            // Can't verify a deleteion of a non-existant var
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }
        else {
            isDeleteOperation = TRUE;
            DataSize = Var->DataSize;
            DMSG("newDS: %x", DataSize);
            Data = Var->BaseAddress + Var->DataOffset;
            DMSG("newdata: %x", Data);
        }
    }

    // NOTE!: This function assumes we have already verified parameters to the 
    //        point where we know whether or not this is a valid delete operation.
    //        Therefore, we assume that !(DataSize) && (Var) means delete. Further, 
    //        we can't assume we have a valid data pointer on a delete so time
    //        checking isn't relevant in this case.

    // Parse parameters
    status = ValidateParameters(Data, DataSize, &signedData, &signedDataSize, &data, &dataSize, &efiTime);
    if (status != TEE_SUCCESS)
    {
        goto Cleanup;
    }
    
    DMSG("DS:%x SDS:%x smdS: %x", DataSize, signedDataSize, dataSize);

    // If we have a time field, make sure it is updated (unless this is an append)
    if ((Attributes.AppendWrite) || (Var == NULL))
    {
        prevEfiTime = NULL;
    }
    else
    {
        // REVISIT: This should be an assert
        if (!(Var->ExtAttribOffset))
        {
            DMSG("ASSERT ExtAttribOffset: %x", Var->ExtAttribOffset);
            status = TEE_ERROR_BAD_PARAMETERS;
            goto Cleanup;
        }

        // Authenticated volatile variables are not implemented, we know this is an offset
        pExtAttrib = (PEXTENDED_ATTRIBUTES)((UINT_PTR)Var + Var->ExtAttribOffset);
        prevEfiTime = &pExtAttrib->EfiTime;
    }

    // If we have new data (i.e., !(isDeleteOperation)), validate prev/new efiTime.
    if (!(isDeleteOperation))
    {
        status = VerifyTime(&efiTime, prevEfiTime);
        if (status != TEE_SUCCESS)
        {
            DMSG("FAILED VerifyTime", Var->ExtAttribOffset);
            goto Cleanup;
        }
    }

    // Integer overflow check.
    if (((UINT32)UnicodeName->Buffer + UnicodeName->Length) < (UINT32)UnicodeName->Buffer)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Calculate data-to-verify size                       sizeof(Attributes)!
    // REVISIT: Verify this                                     \/\/\/
    dataToVerifySize = UnicodeName->Length + sizeof(GUID) + sizeof(ATTRIBUTES) + sizeof(EFI_TIME) + dataSize;

    // Integer overflow check.
    if (dataToVerifySize < dataSize)
    {
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    DMSG("Malloc dataToVerifySize: %x", dataToVerifySize);

    if (!(dataToVerify = TEE_Malloc(dataToVerifySize, TEE_USER_MEM_HINT_NO_FILL_ZERO)))
    {
        status = TEE_ERROR_OUT_OF_MEMORY;
        DMSG("FAILED Malloc");
        goto Cleanup;
    }

    index = 0;

    memmove(dataToVerify + index, UnicodeName->Buffer, UnicodeName->Length);
    index += UnicodeName->Length;

    memmove(dataToVerify + index, VendorGuid, sizeof(GUID));
    index += sizeof(GUID);

    memmove(dataToVerify + index, &Attributes, sizeof(UINT32));
    index += sizeof(ATTRIBUTES);

    memmove(dataToVerify + index, &efiTime, sizeof(EFI_TIME));
    index += sizeof(EFI_TIME);

    memmove(dataToVerify + index, data, dataSize);
    index += dataSize;

    // REVISIT: Should be an assert
    if (!(index == dataToVerifySize))
    {
        DMSG("ASSERT %x (index) != %x (dataToVerifySize)", index, dataToVerifySize);
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    DMSG("IdentifySecureBootVarialbe");

    // Proceed only if this is a secure boot variable
    if (IdentifySecurebootVariable(UnicodeName->Buffer, VendorGuid, &id))
    {
        DMSG("Doing securebootvarauth");

        status = SecureBootVarAuth(id, signedData, signedDataSize, data, dataSize, dataToVerify, dataToVerifySize);
        if (status != TEE_SUCCESS)
        {
            DMSG("FAILED SecureBootVarAuth %x", status);
            goto Cleanup;
        }
    }
    else
    {
        // Private authenticated variables not implemented
        status = TEE_ERROR_NOT_IMPLEMENTED;
        DMSG("Private authenticated variables not implemented");
        goto Cleanup;
    }

    // As per UEFI specification, the driver does not have to append signature values
    // of GUID EFI_IMAGE_SECURITY_DATABASE_GUID which are already present in the variable.
    if ( (Var != NULL) &&
        ((id == SecureBootVariableDB) || (id == SecureBootVariableDBX)) &&
        (Attributes.AppendWrite))
    {
        DMSG("Checking for duplicate signatures");
        status = CheckForDuplicateSignatures(Var, data, dataSize, &duplicatesFound, &newData, &newDataSize);
        if (status != TEE_SUCCESS)
        {
            DMSG("FAILED CheckForDuplicateSignatures: %x", status);
            goto Cleanup;
        }
    }

    if (duplicatesFound)
    {
        *Content = newData;
        *ContentSize = newDataSize;
    }
    else
    {
        *Content = data;
        *ContentSize = dataSize;
    }

    *DuplicateFound = duplicatesFound;

    memset(ExtendedAttributes, 0, sizeof(EXTENDED_ATTRIBUTES));
    ExtendedAttributes->EfiTime = efiTime;

Cleanup:
    return status;
}

static
TEE_Result
ValidateParameters(
    PBYTE        Data,              // IN
    UINT32       DataSize,          // IN
    PBYTE       *SignedData,        // OUT
    UINT32      *SignedDataSize,    // OUT
    PBYTE       *ActualData,        // OUT
    UINT32      *ActualDataSize,    // OUT
    EFI_TIME    *EfiTime            // OUT
)
/*++

    Routine Description:

        Function to parse data parameter from UEFI SetVariable function.
        It is parsed into the signed data field, timestamp, and content.

    Arguments:

        Data - Data parameter from the original SetVariable Function

        DataSize - Size in bytes of Data

        SignedData - Supplies the PKCS#7 Signed Data parsed from Data

        SignedDataSize - Size in bytes of SignedData

        ActualData - Content of the variable

        ActualDataSize - Size in bytes of the variable

        EfiTime - Timestamp parsed from Data

    Returns:

        TEE_Result

--*/
{
    WIN_CERTIFICATE_UEFI_GUID *winCertUefiGuid;
    EFI_VARIABLE_AUTHENTICATION_2 *efiVarAuth2;
    UINT32 winCertUefiGuidSize, efiVarAuth2Size;
    TEE_Result status;

    // Guard against overflow
    if (((UINT32)Data + DataSize) <= (UINT32)Data)
    {
        DMSG("ovflw");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Validate our data size
    winCertUefiGuidSize = sizeof(WIN_CERTIFICATE) + sizeof(GUID);
    efiVarAuth2Size = winCertUefiGuidSize + sizeof(EFI_TIME);
    if (DataSize < efiVarAuth2Size)
    {
        DMSG("vds");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // Check data alignment
    if (((UINT32)Data % __alignof(EFI_VARIABLE_AUTHENTICATION_2)) != 0)
    {
        DMSG("alignment");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    efiVarAuth2 = (EFI_VARIABLE_AUTHENTICATION_2*)Data;
    winCertUefiGuid = (WIN_CERTIFICATE_UEFI_GUID *)&efiVarAuth2->AuthInfo;

    DMSG("eviFarAuth2: %x", efiVarAuth2);
    DMSG("winCertUefiGuid->CertType: %x", winCertUefiGuid->CertType);
    DMSG("EfiCertTypePKCS7Guid: %x", EfiCertTypePKCS7Guid);

    if (memcmp(&winCertUefiGuid->CertType, &EfiCertTypePKCS7Guid, sizeof(GUID)) != 0)
    {
        DMSG("certtype?");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    // All prechecks passed, now get the PKCS#7 signed data value and content
    *EfiTime = efiVarAuth2->TimeStamp;
    if (winCertUefiGuid->Hdr.dwLength < winCertUefiGuidSize)
    {
        DMSG("tmstp");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    *SignedDataSize = winCertUefiGuid->Hdr.dwLength - winCertUefiGuidSize;
    if ((DataSize - efiVarAuth2Size) < *SignedDataSize)
    {
        DMSG("wincerkjjkhsdfh");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    *ActualDataSize = DataSize - efiVarAuth2Size - *SignedDataSize;
    *SignedData = (PBYTE)(&efiVarAuth2->AuthInfo.CertData[0]);
    if ((UINT32)*SignedData + *SignedDataSize <= (UINT32)*SignedData)
    {
        DMSG("otherthing");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    *ActualData = (PBYTE)(*SignedData + *SignedDataSize);
    if ((UINT32)*ActualData + *ActualDataSize <= (UINT32)*ActualData)
    {
        DMSG("last thing");
        status = TEE_ERROR_BAD_PARAMETERS;
        goto Cleanup;
    }

    status = TEE_SUCCESS;
Cleanup:
    return status;
}

static
TEE_Result
SecureBootVarAuth(
    SECUREBOOT_VARIABLE Id,         // IN
    PBYTE AuthenticationData,       // IN
    UINT32 AuthenticationDataSize,  // IN
    PBYTE Data,                     // IN
    UINT32 DataSize,                // IN
    PBYTE DataToVerify,             // IN
    UINT32 DataToVerifySize         // IN
)
/*++

    Routine Description:

        Function to authenticate access to secure boot variable.

    Arguments:

        Id - Enum selecting secureboot variable

        AuthenticationData - PKCS#7 Signed Data to authenticate Data

        AuthenticationDataSize - Size in bytes of AuthenticationData

        Data - Content of the variable

        DataSize - Size in bytes of the variable

        DataToVerify - Content of the data to verify packet.

        DataToVerifySize - Size in bytes of the data to verify packet.

    Returns:

        Status Code

    Notes:

        Comparison with EDKII AuthService::VerifyTimeBasedPayload
         - AuthenticationData === SigData
         - Data === NewData
           - The serialized stream of the UEFI variable info + payload data.
--*/
{
    PDATA_BLOB certs = NULL;
    ULONG numberOfCerts = 0, i;
    SECUREBOOT_VARIABLE var2 = SecureBootVariableEnd;
    BOOLEAN verifyStatus = FALSE;
    UINT8   *signerCerts = NULL;
    UINT8   *rootCert = NULL;
    UINT32  rootCertSize;
    UINT32  signerCertStackSize;
    TEE_Result status;

    if ((Id == SecureBootVariableDB) || (Id == SecureBootVariableDBX))
    {
        DMSG("KEK");
        var2 = SecureBootVariableKEK;
    }

    // TODO: ADD ASSERT ON Id CHECK
    // ASSERT((Id == SecureBootVariablePK) || (Id == SecureBootVariableKEK) ||
    //     (Id == SecureBootVariableDB) || (Id == SecureBootVariableDBX));

    //
    // Perform signature validation and check if we trust the signing certificate
    //
    DMSG("inhere");

    if (SecureBootInUserMode)
    {
        DMSG("SecureBootInUserMode");

        status = PopulateCerts(SecureBootVariablePK, var2, &certs, (PUINT32)&numberOfCerts);
        DMSG("PopulateCerts: %x, certs: %x", status, certs);

        if (status != TEE_SUCCESS)
        {
            goto Cleanup;
        }

        if (certs == NULL)
        {
            status = TEE_ERROR_ACCESS_DENIED;
            goto Cleanup;
        }

        // Iterate through all the certs to find one that verifys OK.
        for (i = 0; i < numberOfCerts; i++)
        {
            if (verifyStatus = Pkcs7Verify(AuthenticationData, AuthenticationDataSize,
                                           certs[i].Data, certs[i].DataSize,
                                           DataToVerify, DataToVerifySize)) 
            {
                break;
            }
        }

        // DEBUG/REVISIT/TODO: REMOVE THIS!!
        verifyStatus = 1;

        if (!verifyStatus)
        {
            status = TEE_ERROR_ACCESS_DENIED;
            goto Cleanup;
        }
    }

    //
    // If in setup mode, only PK needs to be signed by its corresponding PKpriv
    //
    // The provisioning code in EDK2 does not populate any AuthenticationData
    // along with the certificate (see CreateTimeBasedPayload).
    //
    else if (Id == SecureBootVariablePK)
    {
        //
        // In this mode the PK is expected to have been self-signed.
        // First, get signer's certificates from PK variable data.
        //
        if (!(Pkcs7GetSigners(AuthenticationData, AuthenticationDataSize,
                              &signerCerts, &signerCertStackSize,
                              &rootCert, &rootCertSize)))
        {
            status = TEE_ERROR_ACCESS_DENIED;
            goto Cleanup;
        }

        // Second, Verify Pkcs7 AuthenticationData via Pkcs7Verify library.
        if (!(Pkcs7Verify(AuthenticationData, AuthenticationDataSize,
                          rootCert, rootCertSize,
                          DataToVerify, DataToVerifySize)))
        {
            status = TEE_ERROR_ACCESS_DENIED;
            goto Cleanup;
        }
    }
    else
    {
        // PASSED BY DEFAULT
    }

    status = TEE_SUCCESS;

Cleanup:
    for (i = 0; i < numberOfCerts; i++)
    {
        TEE_Free(certs[i].Data);
    }

    TEE_Free(certs);

    if (signerCerts != NULL)
    {
        TEE_Free(signerCerts);
    }

    if (rootCert != NULL)
    {
        TEE_Free(rootCert);
    }

    return status;
}

static
BOOLEAN
IdentifySecurebootVariable(
    PCWSTR VariableName,        // IN
    PCGUID VendorGuid,          // IN
    PSECUREBOOT_VARIABLE Id     // OUT
)
/*++

    Routine Description:

        Function to determine if a variable is one of the known secureboot authenticated variables

    Arguments:

        VariableName - Name of the variable

        VendorGuid - Vendor Guid of the variable

        Id - Enum identifying the secureboot variable

    Returns:

        TRUE if one of the known secureboot authenticated variables

        FALSE otherwise

--*/
{
    UINT32 i;
    BOOLEAN retVal = FALSE;

    for (i = 0; i < SecureBootVariableEnd; i++)
    {
        if ((memcmp(VendorGuid, &SecurebootVariableInfo[i].VendorGuid, sizeof(GUID)) == 0) &&
            (wcscmp(VariableName, SecurebootVariableInfo[i].UnicodeName.Buffer) == 0))
        {
            *Id = SecurebootVariableInfo[i].Id;
            retVal = TRUE;
            break;
        }
    }

    return retVal;
}

static
TEE_Result
VerifyTime(
    EFI_TIME    *FirstTime,
    EFI_TIME    *SecondTime
)
/*++

    Routine Description:

        Verifies EFI time as per UEFI requirements.

    Arguments:

        FirstTime - Timestamp which is checked for correctness

        SecondTime - Optional. If provided should be less than EfiTime

    Return Value:

        TRUE - Success

        FALSE - Failure

--*/
{
    TEE_Result status = TEE_SUCCESS;

    // Some validation on FirstTime
    if ((FirstTime->Pad1 != 0) ||
        (FirstTime->Nanosecond != 0) ||
        (FirstTime->TimeZone != 0) ||
        (FirstTime->Daylight != 0) ||
        (FirstTime->Pad2 != 0))
    {
        DMSG("asdasdasd");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Have an EFI_TIME to compare?
    if (!SecondTime)
    {
        return TEE_SUCCESS;
    }

    // Ensure FirstTime IsBefore SecondTime
    if (!IsBefore(FirstTime, SecondTime))
    {
        DMSG("BBBEEEFFFOOORRREEE");
        return TEE_ERROR_ACCESS_DENIED;
    }

    return TEE_SUCCESS;
}

static
BOOLEAN
IsBefore(
    EFI_TIME    *FirstTime,
    EFI_TIME    *SecondTime
)
{
    if (FirstTime->Year != SecondTime->Year)
    {
        DMSG("y");
        return (FirstTime->Year < SecondTime->Year);
    }
    else if (FirstTime->Month != SecondTime->Month)
    {
        DMSG("m");
        return (FirstTime->Month < SecondTime->Month);
    }
    else if (FirstTime->Day != SecondTime->Day)
    {
        DMSG("d");
        return (FirstTime->Day < SecondTime->Day);
    }
    else if (FirstTime->Hour != SecondTime->Hour)
    {
        DMSG("h");
        return (FirstTime->Hour < SecondTime->Hour);
    }
    else if (FirstTime->Minute != SecondTime->Minute)
    {
        DMSG("m");
        return (FirstTime->Minute < SecondTime->Minute);
    }
    DMSG("s");
    return (FirstTime->Second < SecondTime->Second);
}