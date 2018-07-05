/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

#ifndef _RUNTIMESUPPORT_H_
#define _RUNTIMESUPPORT_H_

// OPTEE provides simple versions of these headers
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

typedef unsigned short int wchar_t;

typedef unsigned long  clock_t;
typedef long           time_t;

#ifndef XMEMCPY
#define XMEMCPY(pdest, psrc, size) memcpy((pdest), (psrc), (size))
#endif

#ifndef XMEMSET
#define XMEMSET(pdest, value, size) memset((pdest), (value), (size))
#endif

#ifndef XSTRLEN
#define XSTRLEN(str) strlen((str))
#endif

#ifndef XSTRNCPY
#define XSTRNCPY(str1,str2,n) strncpy((str1),(str2),(n))
#endif

#ifndef XSTRNCASECMP
int strncasecmp(const char *str1, const char *str2, size_t n);
#define XSTRNCASECMP(str1,str2,n) strncasecmp((str1),(str2),(n))
#endif

#ifndef XSTRNCMP
#define XSTRNCMP(str1,str2,n) strncmp((str1),(str2),(n))
#endif

#ifndef XMEMCMP
#define XMEMCMP(str1,str2,n) memcmp((str1),(str2),(n))
#endif

#ifndef XTOUPPER
int toupper (int c);
#define XTOUPPER(str1) toupper((str1))
#endif

#ifndef XTOLOWER
int tolower (int c);
#define XTOLOWER(str1) tolower((str1))
#endif

#undef  WC_NO_HASHDRBG
#define WC_NO_HASHDRBG

/* Bypass P-RNG and use only HW RNG */
extern int wolfRand(unsigned char* output, unsigned int sz);
#undef  CUSTOM_RAND_GENERATE_BLOCK
#define CUSTOM_RAND_GENERATE_BLOCK  wolfRand
#endif
