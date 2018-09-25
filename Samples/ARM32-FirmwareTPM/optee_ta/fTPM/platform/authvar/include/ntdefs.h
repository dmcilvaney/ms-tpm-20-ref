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
#include <wchar.h>

#ifndef CONST
#define CONST               const
#endif

#ifndef VOID
typedef void VOID, *PVOID;
#endif

#define FALSE   0
#define TRUE    1

#ifndef NULL
#define NULL    ((void *)0)
#define NULL64  ((void * POINTER_64)0)
#endif

#ifndef FORCEINLINE
#define FORCEINLINE   static __inline__
#endif

//
// typedefs
//
typedef char                CHAR;
typedef signed char         INT8;
typedef unsigned char       UCHAR;
typedef unsigned char       UINT8;
typedef unsigned char       BYTE;
typedef short               SHORT;
typedef signed short        INT16;
typedef unsigned short      USHORT;
typedef unsigned short      UINT16;
typedef unsigned short      WORD;
typedef int                 INT;
typedef signed int          INT32;
typedef unsigned int        UINT;
typedef unsigned int        UINT32;
typedef long                LONG;
typedef unsigned long       ULONG;
typedef unsigned long       DWORD;
typedef long long           LONGLONG;
typedef long long           LONG64;
typedef long long           RtlINT64;
typedef unsigned long long  ULONGLONG;
typedef unsigned long long  DWORDLONG;
typedef unsigned long long  ULONG64;
typedef unsigned long long  DWORD64;
typedef unsigned long long  UINT64;

#ifdef _WIN64
typedef signed long long    INT_PTR;
typedef unsigned long long  UINT_PTR;
typedef signed long long    LONG_PTR;
typedef unsigned long long  ULONG_PTR;
#else
typedef int                 INT_PTR;
typedef unsigned int        UINT_PTR;
typedef long                LONG_PTR;
typedef unsigned long       ULONG_PTR;
#endif // WIN64

typedef ULONG_PTR   DWORD_PTR;
typedef LONG_PTR    SSIZE_T;
typedef ULONG_PTR   SIZE_T;

typedef BYTE               *PBYTE;
typedef UINT32             *PUINT32;
typedef UINT64             *PUINT64;
typedef SIZE_T             *PSIZE_T;

 //
 // UNICODE (Wide Character) types
 //
 // NOTE: Constants of the form L"" are 32-bit wide on GCC unless -fshort-wchar.
 // For compatibility with Windows convention we still use 16-bit.
 //
typedef wchar_t WCHAR;

typedef WCHAR *PWCHAR, *LPWCH, *PWCH;
typedef CONST WCHAR *LPCWCH, *PCWCH;

typedef  WCHAR *NWPSTR, *LPWSTR, *PWSTR;
typedef  PWSTR *PZPWSTR;
typedef  CONST PWSTR *PCZPWSTR;
typedef  CONST WCHAR *LPCWSTR, *PCWSTR;
typedef  PCWSTR *PZPCWSTR;
typedef  CONST PCWSTR *PCZPCWSTR;

typedef  WCHAR *PNZWCH;
typedef  CONST WCHAR *PCNZWCH;

//
// ANSI (Multi-byte Character) types
//
typedef CHAR *PCHAR, *LPCH, *PCH;
typedef CONST CHAR *LPCCH, *PCCH;

typedef  CHAR *NPSTR, *LPSTR, *PSTR;
typedef  PSTR *PZPSTR;
typedef  CONST PSTR *PCZPSTR;
typedef  CONST CHAR *LPCSTR, *PCSTR;
typedef  PCSTR *PZPCSTR;
typedef  CONST PCSTR *PCZPCSTR;

typedef  CHAR *PNZCH;
typedef  CONST CHAR *PCNZCH;

typedef UCHAR *PUCHAR;
typedef USHORT *PUSHORT;
typedef ULONG *PULONG;

//
// Unicode strings are counted 16-bit character strings. If they are
// NULL terminated, Length does not include trailing NULL.
//
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

#define UNICODE_NULL ((WCHAR)0) // winnt

#define UNICODE_STRING_MAX_BYTES ((USHORT) 65534) // winnt
#define UNICODE_STRING_MAX_CHARS (32767) // winnt

//
// Boolean
//
typedef UCHAR BOOLEAN;           // winnt
typedef BOOLEAN *PBOOLEAN;       // winnt


//
// Large Integer
//
typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    } DUMMYSTRUCTNAME;
    struct {
        ULONG LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;

//
// Physical address.
//

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

//
// GUID
//
typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
} GUID;

#ifndef __LPGUID_DEFINED__
#define __LPGUID_DEFINED__
typedef GUID *LPGUID;
#endif

#ifndef __LPCGUID_DEFINED__
#define __LPCGUID_DEFINED__
typedef const GUID *LPCGUID;
#endif

#ifndef __PGUID_DEFINED__
#define __PGUID_DEFINED__
typedef GUID *PGUID;
#endif

#ifndef __PCGUID_DEFINED__
#define __PCGUID_DEFINED__
typedef const GUID *PCGUID;
#endif

//
// Misc definitions
//

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

//
// wcs*()
//
static __inline__
int wcscmp(
    const wchar_t * src,
    const wchar_t * dst
)
{
    int ret = 0;

    while ((ret = (int)(*src - *dst)) == 0 && *dst)
        ++src, ++dst;

    if (ret < 0)
        ret = -1;
    else if (ret > 0)
        ret = 1;

    return(ret);
}

static __inline__
size_t wcslen(const wchar_t* str)
{
    size_t len = -1;

    const wchar_t* p = str - 1;

    do {
        ++len;
    } while (*++p != L'\0');

    return len;
}

#define STR_SIZE(var) wcslen(var)==0 ? 0 : ((wcslen(var) + 1) * sizeof(WCHAR))

//
//  Doubly linked list structure.  Can be used as either a list head, or
//  as link words.
//
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

//
//  Singly linked list structure. Can be used as either a list head, or
//  as link words.
//
typedef struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY *Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

//
// rtllistentry inlines
//
FORCEINLINE
VOID
FatalListEntryError(
    PVOID p1,
    PVOID p2,
    PVOID p3
)
{
    TEE_Panic(TEE_ERROR_BAD_STATE);
}

FORCEINLINE
VOID
InitializeListHead(
    PLIST_ENTRY ListHead
)
{
    ListHead->Flink = ListHead->Blink = ListHead;
    return;
}

FORCEINLINE
BOOLEAN
IsListEmpty(
    const LIST_ENTRY * ListHead
)
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
VOID
InsertTailList(
    PLIST_ENTRY ListHead,
    PLIST_ENTRY Entry
)
{
    PLIST_ENTRY PrevEntry;

    PrevEntry = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = PrevEntry;
    if (PrevEntry->Flink != ListHead) {
        FatalListEntryError((PVOID)PrevEntry,
            (PVOID)ListHead,
            (PVOID)PrevEntry->Flink);
    }

    PrevEntry->Flink = Entry;
    ListHead->Blink = Entry;
    return;
}

FORCEINLINE
VOID
AppendTailList(
    PLIST_ENTRY ListHead,
    PLIST_ENTRY ListToAppend
)
{
    PLIST_ENTRY ListEnd = ListHead->Blink;

    RtlpCheckListEntry(ListHead);
    RtlpCheckListEntry(ListToAppend);
    ListHead->Blink->Flink = ListToAppend;
    ListHead->Blink = ListToAppend->Blink;
    ListToAppend->Blink->Flink = ListHead;
    ListToAppend->Blink = ListEnd;
    return;
}

FORCEINLINE
PLIST_ENTRY
RemoveTailList(
    PLIST_ENTRY ListHead
)
{
    PLIST_ENTRY Entry;
    PLIST_ENTRY PrevEntry;

    Entry = ListHead->Blink;
    PrevEntry = Entry->Blink;
    if ((Entry->Flink != ListHead) || (PrevEntry->Flink != Entry)) {
        FatalListEntryError((PVOID)PrevEntry,
            (PVOID)Entry,
            (PVOID)ListHead);
    }

    ListHead->Blink = PrevEntry;
    PrevEntry->Flink = ListHead;
    return Entry;
}