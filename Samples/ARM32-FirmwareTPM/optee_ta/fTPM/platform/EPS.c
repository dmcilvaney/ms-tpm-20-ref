/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

//
// Platform Endorsement Primary Seed
//

#include "TpmError.h"
#include "Admin.h"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define TEE_EPS_SIZE      (256/2)   // From TPM2B_RSA_TEST_PRIME in Hierarchy.c

void
_plat__GetEPS(size_t Size, uint8_t *EndorsementSeed)
{
    TEE_Result Result = TEE_ERROR_ITEM_NOT_FOUND;
    uint8_t EPS[TEE_EPS_SIZE] = { 0 };
    size_t EPSLen;

    IMSG("Size=%d",Size);
    IMSG("EPS=%d",TEE_EPS_SIZE);

    pAssert(Size <= (TEE_EPS_SIZE));

    Result = TEE_GetPropertyAsBinaryBlock(TEE_PROPSET_CURRENT_TA,
                                          "com.microsoft.ta.endorsementSeed",
                                          EPS,
                                          &EPSLen);

    if ((EPSLen < Size) || (Result != TEE_SUCCESS)) {
        // We failed to access the property. We can't continue without it
        // and we can't just fail to manufacture, so randomize EPS and 
        // continue. If necessary, fTPM TA storage can be cleared, or the
        // TA updated, and we can trigger remanufacture and try again.
        _plat__GetEntropy(EndorsementSeed, TEE_EPS_SIZE);
        return;
    }

    memcpy(EndorsementSeed, EPS, Size);

#ifdef fTPMDebug
    {
        uint32_t x;
        uint8_t *seed = EndorsementSeed;
        DMSG("TEE_GetProperty 0x%x, seedLen 0x%x\n", Result, Size);
        for (x = 0; x < Size; x = x + 8) {
            DMSG(" seed(%2.2d): %2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x,%2.2x\n", x,
                seed[x + 0], seed[x + 1], seed[x + 2], seed[x + 3],
                seed[x + 4], seed[x + 5], seed[x + 6], seed[x + 7]);
        }
    }
#endif

    return;
}
