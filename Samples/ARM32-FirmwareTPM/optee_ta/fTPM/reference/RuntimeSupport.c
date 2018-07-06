/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

#include <Implementation.h>

/**
 * Implementation of tolower() commonly found in ctype.h
 * Returns an ASCII character, changing to lowercase if the character is
 * in the range 'A'-'Z'.
 */

int tolower (int c)
{
    if(c >= 'A' && c <= 'Z')
    {
        c -= ('A' - 'a');
    }
    return c;
}

int toupper (int c)
{
    if(c >= 'a' && c <= 'z')
    {
        c += ('A' - 'a');
    }
    return c;
}

/**
 * Copied from ms-iot/optee_os repo: Cyrep.c
 * Remove once optee_os has upstream changes.
 */

/**
 * strncpy - Copy a length-limited, %NUL-terminated string
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 * @count: The maximum number of bytes to copy
 *
 * Note that unlike userspace strncpy, this does not %NUL-pad the buffer.
 * However, the result is not %NUL-terminated if the source exceeds
 * @count bytes.
 */
char * strncpy(char * dest,const char *src,size_t count)
{
    char *tmp = dest;
    while (count-- && (*dest++ = *src++) != '\0')
            /* nothing */;
    return tmp;
}

int strncasecmp(const char *str1, const char *str2, size_t n)
{
    size_t i = 0;
    for(i = 0; i < n && str1[i] && str2[i]; i++)
    {
        char delta = tolower(str1[i]) - tolower(str2[i]);
        if (delta != 0)
        {
            return delta;
        }
    }
    return 0;
}

#ifdef CUSTOM_RAND_GENERATE_BLOCK
#include <tee_internal_api.h>
int wolfRand(unsigned char* output, unsigned int sz)
{
    TEE_GenerateRandom((void *)output, (uint32_t)sz);
    
    return 0;
}
#endif