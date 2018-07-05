/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

#ifndef     _BOOL_H
#define     _BOOL_H

#if defined(TRUE)
#undef TRUE
#endif

#if defined FALSE
#undef FALSE
#endif

typedef int BOOL;
#define FALSE   ((BOOL)0)
#define TRUE    ((BOOL)1)

#endif
