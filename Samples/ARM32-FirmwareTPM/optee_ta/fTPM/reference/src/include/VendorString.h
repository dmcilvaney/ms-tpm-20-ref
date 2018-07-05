/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

#ifndef     _VENDOR_STRING_H
#define     _VENDOR_STRING_H

// Define up to 4-byte values for MANUFACTURER.  This value defines the response
// for TPM_PT_MANUFACTURER in TPM2_GetCapability.
// The following line should be un-commented and a vendor specific string
// should be provided here.
#define    MANUFACTURER    "MSFT"

// The following #if macro may be deleted after a proper MANUFACTURER is provided.
#ifndef MANUFACTURER
#error MANUFACTURER is not provided. \
Please modify include\VendorString.h to provide a specific \
manufacturer name.
#endif

// Define up to 4, 4-byte values. The values must each be 4 bytes long and the last
// value used may contain trailing zeros.
// These values define the response for TPM_PT_VENDOR_STRING_(1-4)
// in TPM2_GetCapability.
// The following line should be un-commented and a vendor specific string
// should be provided here.
// The vendor strings 2-4 may also be defined as appropriately.
#define       VENDOR_STRING_1       "SSE "
#define       VENDOR_STRING_2       "fTPM"
//#define       VENDOR_STRING_3
//#define       VENDOR_STRING_4

// The following #if macro may be deleted after a proper VENDOR_STRING_1
// is provided.
#ifndef VENDOR_STRING_1
#error VENDOR_STRING_1 is not provided. \
Please modify include\VendorString.h to provide a vendor specific \
string.
#endif

// the more significant 32-bits of a vendor-specific value
// indicating the version of the firmware
// The following line should be un-commented and a vendor-specific firmware V1
// should be provided here.
// The FIRMWARE_V2 may also be defined as appropriate.
#define   FIRMWARE_V1         (0x20160210)
// the less significant 32-bits of a vendor-specific value
// indicating the version of the firmware
#define   FIRMWARE_V2         (0x00105400)

// The following #if macro may be deleted after a proper FIRMWARE_V1 is provided.
#ifndef FIRMWARE_V1
#error  FIRMWARE_V1 is not provided. \
Please modify include\VendorString.h to provide a vendor-specific firmware \
version
#endif

#endif
