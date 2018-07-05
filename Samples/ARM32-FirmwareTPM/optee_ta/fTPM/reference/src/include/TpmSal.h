/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

/***
*       TpmSal.h provides a set of #defines that allow SymCrypt to be built
*       in VS.
*
****/

#ifndef _TPM_SAL_H_
#define _TPM_SAL_H_

#ifndef _Out_writes_bytes_

#define _Out_writes_( cbData )
#define _Out_writes_bytes_( cbData )
#define _Out_writes_opt_( cbData )
#define _Out_writes_to_(n, c)
#define _In_reads_( cbBytes )
#define _In_reads_opt_( cbAuthData )
#define _In_reads_bytes_(size)
#define _Inout_updates_( nStates )
#define _Inout_updates_bytes_(size)
#define _Field_size_( size )
#define _Field_range_( min, max )
#define _Writable_elements_(c)
#define _Ret_writes_bytes_to_(n, c)

#define _Analysis_assume_(x)
#define _Analysis_noreturn_

#define _Use_decl_annotations_

#define __success(x)

#define __assume
#define __analysis_assume
#define _In_
#define _Out_
#define __in
#define __in_opt
#define __in_bcount(x)
#define __in_bcount_opt(x)
#define __in_ecount(x)
#define __in_ecount_opt(x)
#define __in_xcount(x)
#define __out
#define __out_ecount(x)
#define __out_ecount_opt(x)
#define __out_ecount_full(x)
#define __out_ecount_part(x, y)
#define __out_bcount(x)
#define __out_bcount_part_opt(x, y)
#define __out_bcount_full(x)
#define __out_xcount(x)
#define __out_xcount_opt(x)
#define __out_ecount_part(x, y)
#define __out_ecount_part_opt(x, y)
#define __out_opt
#define __inout_ecount(x)
#define __inout_bcount(x)
#define __bound
#define __inout
#define __inout_opt
#define __inout_ecount_opt(x)
#define __deref_out_ecount(x)
#define __deref_opt_out_ecount(x)
#define __field_ecount(x)
#define _Post_invalid_
#define _Pre_maybenull_
#define __checkReturn
#define _In_bytecount_(x)

#endif /* no SAL macros defined */

#ifndef _Interlocked_operand_

#define _Interlocked_operand_

#endif


#endif
