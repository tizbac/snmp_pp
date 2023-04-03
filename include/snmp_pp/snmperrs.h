/*_############################################################################
 * _##
 * _##  snmperrs.h
 * _##
 * _##  SNMP++ v3.4
 * _##  -----------------------------------------------
 * _##  Copyright (c) 2001-2021 Jochen Katz, Frank Fock
 * _##
 * _##  This software is based on SNMP++2.6 from Hewlett Packard:
 * _##
 * _##    Copyright (c) 1996
 * _##    Hewlett-Packard Company
 * _##
 * _##  ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.
 * _##  Permission to use, copy, modify, distribute and/or sell this software
 * _##  and/or its documentation is hereby granted without fee. User agrees
 * _##  to display the above copyright notice and this license notice in all
 * _##  copies of the software and any documentation of the software. User
 * _##  agrees to assume all liability for the use of the software;
 * _##  Hewlett-Packard, Frank Fock, and Jochen Katz make no representations
 * _##  about the suitability of this software for any purpose. It is provided
 * _##  "AS-IS" without warranty of any kind, either express or implied. User
 * _##  hereby grants a royalty-free license to any and all derivatives based
 * _##  upon this software code base.
 * _##
 * _##########################################################################*/
/*===================================================================
 *
 * Copyright (c) 1999
 * Hewlett-Packard Company
 *
 * ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.
 * Permission to use, copy, modify, distribute and/or sell this software
 * and/or its documentation is hereby granted without fee. User agrees
 * to display the above copyright notice and this license notice in all
 * copies of the software and any documentation of the software. User
 * agrees to assume all liability for the use of the software; Hewlett-Packard
 * makes no representations about the suitability of this software for any
 * purpose. It is provided "AS-IS without warranty of any kind,either express
 * or implied. User hereby grants a royalty-free license to any and all
 * derivatives based upon this software code base.
 *
 *
 * SNMP++ S N M P E R R S. H
 *
 * SNMP++ ERROR CODE AND STRING DEFINITIONS
 *
 * DESCRIPTION:
 * Definition of error macros and error strings
 *
 * DESIGN + AUTHOR:  Jeff Meyer
 * ============================================================================*/

#ifndef _SNMP_SNMPERRS_H_
#define _SNMP_SNMPERRS_H_

#include "snmp_pp/config_snmp_pp.h"

#include <libsnmp.h>

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp
{
#endif

//-------[ Positive SNMP ++ Error Return Codes ]------------------------------

/** @name Pdu error codes
 * These values are error status values from RFC 1905
 *
 * The values can be returned via Pdu::get_error_status()
 */
//@{
#define SNMP_ERROR_SUCCESS          0  //!< Success Status
#define SNMP_ERROR_TOO_BIG          1  //!< Pdu encoding too big
#define SNMP_ERROR_NO_SUCH_NAME     2  //!< No such VB name, see error index
#define SNMP_ERROR_BAD_VALUE        3  //!< Bad Vb
#define SNMP_ERROR_READ_ONLY        4  //!< VB is read only, see error index
#define SNMP_ERROR_GENERAL_VB_ERR   5  //!< General VB error, see error index
#define SNMP_ERROR_NO_ACCESS        6  //!< No access to MIBs data
#define SNMP_ERROR_WRONG_TYPE       7  //!< Requested type was incorrect
#define SNMP_ERROR_WRONG_LENGTH     8  //!< Request Pdu has inccorect length
#define SNMP_ERROR_WRONG_ENCODING   9  //!< Request Pdu has wrong encoding
#define SNMP_ERROR_WRONG_VALUE      10 //!< Request Pdu has wrong value
#define SNMP_ERROR_NO_CREATION      11 //!< Unable to create object specified
#define SNMP_ERROR_INCONSIST_VAL    12 //!< Inconsistent value in request
#define SNMP_ERROR_RESOURCE_UNAVAIL 13 //!< Resources unavailable
#define SNMP_ERROR_COMITFAIL \
    14 //!< Unable to commit (for backward compatibility)
#define SNMP_ERROR_COMMITFAIL    14 //!< Unable to commit
#define SNMP_ERROR_UNDO_FAIL     15 //!< Unable to undo
#define SNMP_ERROR_AUTH_ERR      16 //!< Authorization error
#define SNMP_ERROR_NOT_WRITEABLE 17 //!< Mib Object not writeable
#define SNMP_ERROR_INCONSIS_NAME 18 //!< Inconsistent naming used
//@}

//-------[ Negative SNMP ++ Result/Error Return Codes ]-------------------

/** @name Snmp class return codes
 */
//@{

// General
#define SNMP_CLASS_SUCCESS          0  //!< success
#define SNMP_CLASS_ERROR            -1 //!< general error
#define SNMP_CLASS_RESOURCE_UNAVAIL -2 //!< e.g., malloc failed
#define SNMP_CLASS_INTERNAL_ERROR   -3 //!< unexpected / internal error
#define SNMP_CLASS_UNSUPPORTED      -4 //!< unsupported function

// Callback reasons:
#define SNMP_CLASS_TIMEOUT        -5 //!< outstanding request timed out
#define SNMP_CLASS_ASYNC_RESPONSE -6 //!< received response for outstd request
#define SNMP_CLASS_NOTIFICATION   -7 //!< received notification (trap/inform)
#define SNMP_CLASS_SESSION_DESTROYED \
    -8 //!< snmp::destroyed with oustanding reqs pending

// Snmp Class:
#define SNMP_CLASS_INVALID          -10 //!< snmp::mf called on invalid instance
#define SNMP_CLASS_INVALID_PDU      -11 //!< invalid pdu passed to mf
#define SNMP_CLASS_INVALID_TARGET   -12 //!< invalid target passed to mf
#define SNMP_CLASS_INVALID_CALLBACK -13 //!< invalid callback to mf
#define SNMP_CLASS_INVALID_REQID    -14 //!< invalid request id to cancel
#define SNMP_CLASS_INVALID_NOTIFYID -15 //!< missing trap/inform oid
#define SNMP_CLASS_INVALID_OPERATION \
    -16 //!< snmp operation not allowed for specified target
#define SNMP_CLASS_INVALID_OID     -17 //!< invalid oid passed to mf
#define SNMP_CLASS_INVALID_ADDRESS -18 //!< invalid address passed to mf
#define SNMP_CLASS_ERR_STATUS_SET \
    -19 //!< agent returned response pdu with error_status set

// Transport Errors:
#define SNMP_CLASS_TL_UNSUPPORTED   -20 //!< transport unsupported
#define SNMP_CLASS_TL_IN_USE        -21 //!< transport in use
#define SNMP_CLASS_TL_FAILED        -22 //!< transport operation failed
#define SNMP_CLASS_TL_ACCESS_DENIED -23 //!< transport missing rights

// extras
#define SNMP_CLASS_SHUTDOWN -24 //!< used for back door shutdown

// ASN.1 parse errors
#define SNMP_CLASS_BADVERSION -50 //!< unsupported version
#define SNMP_CLASS_ASN1ERROR  -51 //!< used for ASN.1 parse errors
//@}

#define MAX_POS_ERROR SNMP_ERROR_INCONSIS_NAME
#define MAX_NEG_ERROR SNMP_CLASS_SHUTDOWN

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif

#endif // _SNMP_SNMPERRS_H_
