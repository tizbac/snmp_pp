/*_############################################################################
  _##
  _##  asn1.cpp
  _##
  _##  SNMP++ v3.4
  _##  -----------------------------------------------
  _##  Copyright (c) 2001-2021 Jochen Katz, Frank Fock
  _##
  _##  This software is based on SNMP++2.6 from Hewlett Packard:
  _##
  _##    Copyright (c) 1996
  _##    Hewlett-Packard Company
  _##
  _##  ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.
  _##  Permission to use, copy, modify, distribute and/or sell this software
  _##  and/or its documentation is hereby granted without fee. User agrees
  _##  to display the above copyright notice and this license notice in all
  _##  copies of the software and any documentation of the software. User
  _##  agrees to assume all liability for the use of the software;
  _##  Hewlett-Packard, Frank Fock, and Jochen Katz make no representations
  _##  about the suitability of this software for any purpose. It is provided
  _##  "AS-IS" without warranty of any kind, either express or implied. User
  _##  hereby grants a royalty-free license to any and all derivatives based
  _##  upon this software code base.
  _##
  _##########################################################################*/

/*===================================================================
  Copyright (c) 1999
  Hewlett-Packard Company

  ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.
  Permission to use, copy, modify, distribute and/or sell this software
  and/or its documentation is hereby granted without fee. User agrees
  to display the above copyright notice and this license notice in all
  copies of the software and any documentation of the software. User
  agrees to assume all liability for the use of the software; Hewlett-Packard
  makes no representations about the suitability of this software for any
  purpose. It is provided "AS-IS" without warranty of any kind,either express
  or implied. User hereby grants a royalty-free license to any and all
  derivatives based upon this software code base.

  A S N 1. C P P

  ASN encoder / decoder implementation

  DESIGN + AUTHOR:  Peter E. Mellquist
=====================================================================*/

#include "snmp_pp/asn1.h"

#include "snmp_pp/config_snmp_pp.h"
#include "snmp_pp/log.h"
#include "snmp_pp/snmperrs.h"
#include "snmp_pp/v3.h"

#include <cassert>
#include <libsnmp.h>

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp
{
#endif

#ifndef _NO_LOGGING
static const char* loggerModuleName = "snmp++.asn1";
#endif

/*
 * asn_parse_int - pulls a long out of an ASN int type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_parse_int(
    unsigned char* data, int* datalength, unsigned char* type, SmiINT32* intp)
{
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     *       timestamp   0x43 asnlength byte {byte}*
     */
    unsigned char* bufp       = data;
    uint32_t       asn_length = 0;
    long           value      = 0;

    *type = *bufp++;
    if ((*type != 0x02) && (*type != 0x43) && (*type != 0x41))
    {
        ASNERROR("Wrong Type. Not an integer");
        return nullptr;
    }
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == nullptr)
    {
        ASNERROR("bad length");
        return nullptr;
    }
    if ((asn_length + (bufp - data)) > (uint32_t)(*datalength))
    {
        ASNERROR("overflow of message (int)");
        return nullptr;
    }
    if (asn_length > sizeof(*intp))
    {
        ASNERROR("I don't support such large integers");
        return nullptr;
    }
    *datalength -= (int)asn_length + SAFE_INT_CAST(bufp - data);
    if (*bufp & 0x80) value = -1; /* integer is negative */

    // FIXME: The result of the left shift is undefined because the left
    // operand is negative! CK
    // [clang-analyzer-core.UndefinedBinaryOperatorResult]
    while (asn_length--) value = (value << 8) | *bufp++;

    *intp = value;
    return bufp;
}

/*
 * asn_parse_unsigned_int - pulls an uint32_t out of an ASN int type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_parse_unsigned_int(
    unsigned char* data, int* datalength, unsigned char* type, SmiUINT32* intp)
{
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     *                   0x43 asnlength byte {byte}*
     */
    unsigned char* bufp       = data;
    uint32_t       asn_length = 0;
    uint32_t       value      = 0;

    // get the type
    *type = *bufp++;
    if ((*type != 0x02) && (*type != 0x43) && (*type != 0x41)
        && (*type != 0x42) && (*type != 0x47))
    {
        ASNERROR("Wrong Type. Not an unsigned integer");
        return nullptr;
    }

    // pick up the len
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == nullptr)
    {
        ASNERROR("bad length");
        return nullptr;
    }

    // check the len for message overflow
    if ((asn_length + (bufp - data)) > (uint32_t)(*datalength))
    {
        ASNERROR("overflow of message (uint)");
        return nullptr;
    }

    // check for legal uint size
    if ((asn_length > 5) || ((asn_length > 4) && (*bufp != 0x00)))
    {
        ASNERROR("I don't support such large integers");
        return nullptr;
    }

    // check for leading  0 octet
    if (*bufp == 0x00)
    {
        bufp++;
        asn_length--;
    }

    // fix the returned data length value
    *datalength -= (int)asn_length + SAFE_INT_CAST(bufp - data);

    // calculate the value
    for (long i = 0; i < (long)asn_length; i++)
        value = (value << 8) + (uint32_t)*bufp++;

    *intp = value; // assign return value

    return bufp;   // return the bumped pointer
}

/*
 * asn_build_int - builds an ASN object containing an integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_build_int(unsigned char* data, int* datalength,
    const unsigned char type, const SmiINT32* intp)
{
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     */
    int64_t       integer = *intp;
    unsigned long mask    = 0;
    int           intsize = sizeof(int32_t);

    /* Truncate "unnecessary" bytes off of the most significant end of this
     * 2's complement integer.  There should be no sequence of 9
     * consecutive 1's or 0's at the most significant end of the
     * integer.
     */
    mask = 0x1FFul << ((8 * (sizeof(int32_t) - 1)) - 1);
    /* mask is 0xFF800000 on a big-endian machine */
    while (
        (((integer & mask) == 0) || ((integer & mask) == mask)) && intsize > 1)
    {
        intsize--;
        integer <<= 8;
    }
    data = asn_build_header(data, datalength, type, intsize);
    if (data == nullptr) return nullptr;
    if (*datalength < intsize) return nullptr;
    *datalength -= intsize;
    mask = 0xFFul << (8 * (sizeof(int32_t) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    while (intsize--)
    {
        *data++ =
            (unsigned char)((integer & mask) >> (8 * (sizeof(int32_t) - 1)));
        integer <<= 8;
    }
    return data;
}

/*
 * asn_build_unsigned_int - builds an ASN object containing an integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_build_unsigned_int(unsigned char* data, // modified data
    int*          datalength, // returned buffer length
    unsigned char type,       // SMI type
    SmiUINT32*    intp)          // Uint to encode
{
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     */
    uint32_t const u_integer     = *intp;
    long           u_integer_len = 0;
    long           x             = 0;

    // figure out the len
    if (((u_integer >> 24) & 0xFF) != 0)
        u_integer_len = 4;
    else if (((u_integer >> 16) & 0xFF) != 0)
        u_integer_len = 3;
    else if (((u_integer >> 8) & 0xFF) != 0)
        u_integer_len = 2;
    else
        u_integer_len = 1;

    // check for 5 byte len where first byte will be a null
    if (((u_integer >> (8 * (u_integer_len - 1))) & 0x080) != 0)
    {
        u_integer_len++;
    }

    // build up the header
    data = asn_build_header(data, datalength, type, u_integer_len);
    if (data == nullptr) return nullptr;
    if (*datalength < u_integer_len) return nullptr;

    // special case, add a null byte for len of 5
    if (u_integer_len == 5)
    {
        *data++ = 0;
        for (x = 1; x < u_integer_len; x++)
            *data++ = (unsigned char)(u_integer
                >> (8 * ((u_integer_len - 1) - x) & 0xFF));
    }
    else
    {
        for (x = 0; x < u_integer_len; x++)
            *data++ = (unsigned char)(u_integer
                >> (8 * ((u_integer_len - 1) - x) & 0xFF));
    }
    *datalength -= u_integer_len;
    return data;
}

/*
 * asn_parse_string - pulls an octet string out of an ASN octet string type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "string" is filled with the octet string.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_parse_string(unsigned char* data, int* datalength,
    unsigned char* type, unsigned char* str, int* strlength)
{
    /*
     * ASN.1 octet string ::= primstring | cmpdstring
     * primstring ::= 0x04 asnlength byte {byte}*
     * cmpdstring ::= 0x24 asnlength string {string}*
     * ipaddress  ::= 0x40 4 byte byte byte byte
     */
    unsigned char* bufp       = data;
    uint32_t       asn_length = 0;

    *type = *bufp++;
    if ((*type != 0x04) && (*type != 0x24) && (*type != 0x40)
        && (*type != 0x44) && (*type != 0x45))
    {
        ASNERROR("asn parse string: Wrong Type. Not a string");
        return nullptr;
    }
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == nullptr) return nullptr;
    if ((asn_length + (bufp - data)) > (uint32_t)(*datalength))
    {
        ASNERROR("asn parse string: overflow of message");
        return nullptr;
    }
    if ((int)asn_length > *strlength)
    {
        ASNERROR("asn parse string: String to parse is longer than buffer, "
                 "aborting parsing.");
        return nullptr;
    }

    memcpy(str, bufp, asn_length);
    *strlength = (int)asn_length;
    *datalength -= (int)asn_length + SAFE_INT_CAST(bufp - data);
    return bufp + asn_length;
}

/*
 * asn_build_string - Builds an ASN octet string object containing the input
 * string. On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_build_string(unsigned char* data, int* datalength,
    const unsigned char type, const unsigned char* string, const int strlength)
{
    /*
     * ASN.1 octet string ::= primstring | cmpdstring
     * primstring ::= 0x04 asnlength byte {byte}*
     * cmpdstring ::= 0x24 asnlength string {string}*
     * This code will never send a compound string.
     */
    data = asn_build_header(data, datalength, type, strlength);
    if (data == nullptr) return nullptr;
    if (*datalength < strlength) return nullptr;

    memcpy(data, string, strlength);
    *datalength -= strlength;
    return data + strlength;
}

/*
 * asn_parse_header - interprets the ID and length of the current object.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
unsigned char* asn_parse_header(
    unsigned char* data, int* datalength, unsigned char* type)
{
    unsigned char* bufp       = data;
    uint32_t       asn_length = 0;

    /* this only works on data types < 30, i.e. no extension octets */
    if (IS_EXTENSION_ID(*bufp))
    {
        ASNERROR("can't process ID >= 30");
        return nullptr;
    }
    *type = *bufp;
    bufp  = asn_parse_length(bufp + 1, &asn_length);
    if (bufp == nullptr) return nullptr;
    int const header_len = SAFE_INT_CAST(bufp - data);
    if ((uint32_t)(header_len + asn_length) > (uint32_t)*datalength)
    {
        ASNERROR("asn length too long");
        return nullptr;
    }
    *datalength = (int)asn_length;
    return bufp;
}

/*
 * asn_build_header - builds an ASN header for an object with the ID and
 * length specified.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  This only works on data types < 30, i.e. no extension octets.
 *  The maximum length is 0xFFFF;
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
unsigned char* asn_build_header(
    unsigned char* data, int* datalength, unsigned char type, int length)
{
    if (*datalength < 1) return nullptr;
    *data++ = type;
    (*datalength)--;
    return asn_build_length(data, datalength, length);
}

/*
 * asn_build_sequence - builds an ASN header for a sequence with the ID and
 * length specified.
 *
 *  This only works on data types < 30, i.e. no extension octets.
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
unsigned char* asn_build_sequence(
    unsigned char* data, int* datalength, unsigned char type, int length)
{
    if (*datalength < 2) /* need at least two octets for a sequence */
    {
        ASNERROR("build_sequence");
        return nullptr;
    }
    *data++ = type;
    (*datalength)--;

    unsigned char* data_with_length =
        asn_build_length(data, datalength, length);
    if (data_with_length == nullptr)
    {
        (*datalength)++; /* correct datalength to emulate old behavior of
                            build_sequence */
        return nullptr;
    }

    return data_with_length;
}

/*
 * asn_parse_length - interprets the length of the current object.
 *  On exit, length contains the value of this length field.
 *
 *  Returns a pointer to the first byte after this length
 *  field (aka: the start of the data field).
 *  Returns NULL on any error.
 */
unsigned char* asn_parse_length(unsigned char* data, uint32_t* length)
{
    unsigned char lengthbyte = *data;
    *length                  = 0;
    if (lengthbyte & ASN_LONG_LEN)
    {
        lengthbyte &= ~ASN_LONG_LEN; /* turn MSb off */
        if (lengthbyte == 0)
        {
            ASNERROR("We don't support indefinite lengths");
            return nullptr;
        }
        if (lengthbyte > sizeof(int))
        {
            ASNERROR("we can't support data lengths that long");
            return nullptr;
        }
        for (int i = 0; i < lengthbyte; i++)
        {
            *length = (*length << 8) + *(data + 1 + i);
        }
        // check for length greater than 2^31
        if (*length > 0x80000000ul)
        {
            ASNERROR("SNMP does not support data lengths > 2^31");
            return nullptr;
        }
        return data + lengthbyte + 1;
    }
    else
    { /* short asnlength */
        *length = (long)lengthbyte;
        return data + 1;
    }
}

unsigned char* asn_build_length(
    unsigned char* data, int* datalength, int length)
{
    unsigned char* start_data = data;

    /* no indefinite lengths sent */
    if (length < 0x80)
    {
        if (*datalength < 1)
        {
            ASNERROR("build_length");
            return nullptr;
        }
        *data++ = (unsigned char)length;
    }
    else if (length <= 0xFF)
    {
        if (*datalength < 2)
        {
            ASNERROR("build_length");
            return nullptr;
        }
        *data++ = (unsigned char)(0x01 | ASN_LONG_LEN);
        *data++ = (unsigned char)length;
    }
    else if (length <= 0xFFFF)
    { /* 0xFF < length <= 0xFFFF */
        if (*datalength < 3)
        {
            ASNERROR("build_length");
            return nullptr;
        }
        *data++ = (unsigned char)(0x02 | ASN_LONG_LEN);
        *data++ = (unsigned char)((length >> 8) & 0xFF);
        *data++ = (unsigned char)(length & 0xFF);
    }
    else if (length <= 0xFFFFFF)
    { /* 0xFF < length <= 0xFFFF */
        if (*datalength < 4)
        {
            ASNERROR("build_length");
            return nullptr;
        }
        *data++ = (unsigned char)(0x03 | ASN_LONG_LEN);
        *data++ = (unsigned char)((length >> 16) & 0xFF);
        *data++ = (unsigned char)((length >> 8) & 0xFF);
        *data++ = (unsigned char)(length & 0xFF);
    }
    else
    {
        if (*datalength < 5)
        {
            ASNERROR("build_length");
            return nullptr;
        }
        *data++ = (unsigned char)(0x04 | ASN_LONG_LEN);
        *data++ = (unsigned char)((length >> 24) & 0xFF);
        *data++ = (unsigned char)((length >> 16) & 0xFF);
        *data++ = (unsigned char)((length >> 8) & 0xFF);
        *data++ = (unsigned char)(length & 0xFF);
    }
    *datalength -= SAFE_INT_CAST(data - start_data);
    return data;
}

/*
 * asn_parse_objid - pulls an object indentifier out of an ASN object
 * identifier type. On entry, datalength is input as the number of valid bytes
 * following "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "objid" is filled with the object identifier.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_parse_objid(unsigned char* data, int* datalength,
    unsigned char* type, oid_t* objid, int* objidlength)
{
    /*
     * ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
     * subidentifier ::= {leadingbyte}* lastbyte
     * leadingbyte ::= 1 7bitvalue
     * lastbyte ::= 0 7bitvalue
     */
    unsigned char* bufp          = data;
    oid_t*         oidp          = objid + 1;
    uint32_t       subidentifier = 0;
    long           length        = 0;
    uint32_t       asn_length    = 0;

    *type = *bufp++;
    if (*type != 0x06)
    {
        ASNERROR("Wrong Type. Not an oid");
        return nullptr;
    }
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == nullptr) return nullptr;
    if ((asn_length + (bufp - data)) > (uint32_t)(*datalength))
    {
        ASNERROR("overflow of message (objid)");
        return nullptr;
    }
    *datalength -= (int)asn_length + SAFE_INT_CAST(bufp - data);

    /* Handle invalid object identifier encodings of the form 06 00 robustly */
    if (asn_length == 0) objid[0] = objid[1] = 0;

    length = asn_length;
    (*objidlength)--; /* account for expansion of first byte */
    while (length > 0 && (*objidlength)-- > 0)
    {
        subidentifier = 0;
        do { /* shift and add in low order 7 bits */
            subidentifier =
                (subidentifier << 7) + (*(unsigned char*)bufp & ~ASN_BIT8);
            length--;
        } while ((*(unsigned char*)bufp++ & ASN_BIT8)
            && length > 0); /* last byte has high bit clear */
        if (subidentifier > (uint32_t)MAX_SUBID)
        {
            ASNERROR("subidentifier too long");
            return nullptr;
        }
        *oidp++ = (oid_t)subidentifier;
    }

    /*
     * The first two subidentifiers are encoded into the first component
     * with the value (X * 40) + Y, where:
     * X is the value of the first subidentifier.
     * Y is the value of the second subidentifier.
     */
    subidentifier = (uint32_t)objid[1];
    if (subidentifier == 0x2B)
    {
        objid[0] = 1;
        objid[1] = 3;
    }
    else if (subidentifier < 40)
    {
        objid[0] = 0;
        objid[1] = (oid_t)subidentifier;
    }
    else if (subidentifier < 80)
    {
        objid[0] = 1;
        objid[1] = (oid_t)(subidentifier - 40);
    }
    else
    {
        objid[0] = 2;
        objid[1] = (oid_t)(subidentifier - 80);
    }
    *objidlength = (int)(oidp - objid);
    return bufp;
}

/*
 * asn_build_objid - Builds an ASN object identifier object containing the
 * input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_build_objid(unsigned char* data, int* datalength,
    unsigned char type, oid_t* objid, int objidlength)
{
    /*
     * ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
     * subidentifier ::= {leadingbyte}* lastbyte
     * leadingbyte ::= 1 7bitvalue
     * lastbyte ::= 0 7bitvalue
     */
    // F.Fock correct buffer size must be 5*8bit*MAX_OID_LEN
    unsigned char  buf[MAX_OID_LEN * 5];
    unsigned char* bp        = buf;
    oid_t*         op        = objid;
    int            asnlength = 0;

    if (objidlength > MAX_OID_LEN)
    {
        ASNERROR("Too many sub-identifiers.");
        objidlength = MAX_OID_LEN;
    }
    if (objidlength < 2)
    {
        *bp++       = 0;
        objidlength = 0;
    }
    else
    {
        asn_build_subid(op[1] + (op[0] * 40), bp);
        objidlength -= 2;
        op += 2;
    }

    while (objidlength-- > 0) { asn_build_subid(*op++, bp); }
    asnlength = SAFE_INT_CAST(bp - buf);
    data      = asn_build_header(data, datalength, type, asnlength);
    if (data == nullptr) return nullptr;
    if (*datalength < asnlength) return nullptr;

    memcpy((char*)data, (char*)buf, asnlength);
    *datalength -= asnlength;
    return data + asnlength;
}

/**
 * Add the given sub-identifier to the OID byte buffer and forward its pointer
 * accordingly for appending the next one.
 * @param subid
 *    the sub-identifier (32-bit unsigned) to add.
 * @param bp
 *    the buffer pointer. On return, the pointer will be increased at least
 *    by one (character) and at most by five.
 */
void asn_build_subid(uint32_t subid, unsigned char*& bp)
{
    if (subid < 127)
    { /* off by one? */
        *bp++ = (unsigned char)subid;
    }
    else
    {
        uint32_t testmask = 0;
        int      testbits = 0;
        uint32_t mask     = 0x7F; /* handle subid == 0 case */
        int      bits     = 0;
        /* testmask *MUST* !!!! be of an unsigned type */
        for (testmask = 0x7F, testbits = 0; testmask != 0;
             testmask <<= 7, testbits += 7)
        {
            if (subid & testmask)
            { /* if any bits set */
                mask = testmask;
                bits = testbits;
            }
        }
        /* mask can't be zero here */
        for (; mask != 0x7F; mask >>= 7, bits -= 7)
        {
            /* fix a mask that got truncated above */
            if (mask == 0x1E00000) mask = 0xFE00000;
            *bp++ = (unsigned char)(((subid & mask) >> bits) | ASN_BIT8);
        }
        *bp++ = (unsigned char)(subid & mask);
    }
}

/*
 * asn_parse_null - Interprets an ASN null type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_parse_null(
    unsigned char* data, int* datalength, unsigned char* type)
{
    /*
     * ASN.1 null ::= 0x05 0x00
     */
    unsigned char* bufp       = data;
    uint32_t       asn_length = 0;

    *type = *bufp++;
    if (*type != 0x05)
    {
        ASNERROR("Wrong Type. Not a null");
        return nullptr;
    }
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == nullptr) return nullptr;
    if (asn_length != 0)
    {
        ASNERROR("Malformed NULL");
        return nullptr;
    }
    *datalength -= SAFE_INT_CAST(bufp - data);
    return bufp + asn_length;
}

/*
 * asn_build_null - Builds an ASN null object.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_build_null(
    unsigned char* data, int* datalength, unsigned char type)
{
    /*
     * ASN.1 null ::= 0x05 0x00
     */
    return asn_build_header(data, datalength, type, 0);
}

/*
 * asn_parse_bitstring - pulls a bitstring out of an ASN bitstring type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "string" is filled with the bit string.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_parse_bitstring(unsigned char* data, int* datalength,
    unsigned char* type, unsigned char* string, int* strlength)
{
    /*
     * bitstring ::= 0x03 asnlength unused {byte}*
     */
    unsigned char* bufp       = data;
    uint32_t       asn_length = 0;

    *type = *bufp++;
    if (*type != 0x03)
    {
        ASNERROR("Wrong Type. Not a bitstring");
        return nullptr;
    }
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == nullptr) return nullptr;
    if ((asn_length + (bufp - data)) > (uint32_t)(*datalength))
    {
        ASNERROR("overflow of message (bitstring)");
        return nullptr;
    }
    if ((int)asn_length > *strlength)
    {
        ASNERROR("I don't support such long bitstrings");
        return nullptr;
    }
    if (asn_length < 1)
    {
        ASNERROR("Invalid bitstring");
        return nullptr;
    }
    if (*bufp > 7)
    {
        ASNERROR("Invalid bitstring");
        return nullptr;
    }

    memcpy((char*)string, (char*)bufp, (int)asn_length);
    *strlength = (int)asn_length;
    *datalength -= (int)asn_length + SAFE_INT_CAST(bufp - data);
    return bufp + asn_length;
}

/*
 * asn_build_bitstring - Builds an ASN bit string object containing the
 * input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_build_bitstring(unsigned char* data, int* datalength,
    unsigned char type, unsigned char* string, int strlength)
{
    /*
     * ASN.1 bit string ::= 0x03 asnlength unused {byte}*
     */
    if (strlength < 1 || *string > 7)
    {
        ASNERROR("Building invalid bitstring");
        return nullptr;
    }
    data = asn_build_header(data, datalength, type, strlength);
    if (data == nullptr) return nullptr;
    if (*datalength < strlength) return nullptr;

    memcpy((char*)data, (char*)string, strlength);
    *datalength -= strlength;
    return data + strlength;
}

/*
 * asn_parse_unsigned_int64 - pulls a 64 bit uint32_t out of an ASN int
 * type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_parse_unsigned_int64(unsigned char* data, int* datalength,
    unsigned char* type, struct counter64* cp)
{
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     */
    unsigned char* bufp       = data;
    uint32_t       asn_length = 0;
    uint32_t       low = 0, high = 0;

    *type = *bufp++;
    if ((*type != 0x02) && (*type != 0x46))
    {
        ASNERROR("Wrong Type. Not an integer 64");
        return nullptr;
    }
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == nullptr)
    {
        ASNERROR("bad length");
        return nullptr;
    }
    if ((asn_length + (bufp - data)) > (uint32_t)(*datalength))
    {
        ASNERROR("overflow of message (uint64)");
        return nullptr;
    }
    if (((int)asn_length > 9) || (((int)asn_length == 9) && *bufp != 0x00))
    {
        ASNERROR("I don't support such large integers");
        return nullptr;
    }
    *datalength -= (int)asn_length + SAFE_INT_CAST(bufp - data);
    if (*bufp & 0x80)
    {
        low  = (uint32_t)-1; // integer is negative
        high = (uint32_t)-1;
    }
    while (asn_length--)
    {
        high = (high << 8) | ((low & 0xFF000000) >> 24);
        low  = ((low << 8) | *bufp++) & 0xFFFFFFFF;
    }
    cp->low  = low;
    cp->high = high;

    return bufp;
}

/*
 * asn_build_unsigned_int64 - builds an ASN object containing a 64 bit integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
unsigned char* asn_build_unsigned_int64(unsigned char* data, int* datalength,
    unsigned char type, struct counter64* cp)
{
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     */
    uint32_t       low           = cp->low;
    uint32_t       high          = cp->high;
    uint32_t const mask          = 0xFF000000ul;
    int            add_null_byte = 0;
    int            intsize       = 8;

    if (((high & mask) >> 24) & 0x80)
    {
        /* if MSB is set */
        add_null_byte = 1;
        intsize++;
    }
    else
    {
        /*
         * Truncate "unnecessary" bytes off of the most significant end of this
         * 2's complement integer. There should be no sequence of 9 consecutive
         * 1's or 0's at the most significant end of the integer.
         */
        uint32_t const mask2 = 0xFF800000ul;
        while ((((high & mask2) == 0) || ((high & mask2) == mask2))
            && (intsize > 1))
        {
            intsize--;
            high = (high << 8) | ((low & mask) >> 24);
            low <<= 8;
        }
    }
    data = asn_build_header(data, datalength, type, intsize);
    if (data == nullptr) return nullptr;
    if (*datalength < intsize) return nullptr;
    *datalength -= intsize;
    if (add_null_byte == 1)
    {
        *data++ = 0;
        intsize--;
    }
    while (intsize--)
    {
        *data++ = (unsigned char)((high & mask) >> 24);
        high    = (high << 8) | ((low & mask) >> 24);
        low <<= 8;
    }
    return data;
}

// create a pdu
struct snmp_pdu* snmp_pdu_create(int command)
{
    struct snmp_pdu* pdu = nullptr;

    pdu = (struct snmp_pdu*)malloc(sizeof(struct snmp_pdu));
    if (!pdu) return pdu;
    memset((char*)pdu, 0, sizeof(struct snmp_pdu));
    pdu->command = command;
#ifdef _SNMPv3
    pdu->msgid = 0;
#endif
    pdu->errstat           = 0;
    pdu->errindex          = 0;
    pdu->enterprise        = nullptr;
    pdu->enterprise_length = 0;
    pdu->variables         = nullptr;
    return pdu;
}

// free content and clear pointers
void clear_pdu(struct snmp_pdu* pdu, bool clear_all)
{
    struct variable_list* vp = pdu->variables;
    while (vp)
    {
        if (vp->name) free((char*)vp->name);             // free the oid part
        if (vp->val.string) free((char*)vp->val.string); // free deep data
        struct variable_list* ovp = vp;
        vp                        = vp->next_variable;   // go to the next one
        free((char*)ovp);                                // free up vb itself
    }
    pdu->variables = nullptr;

    // if enterprise free it up
    if (pdu->enterprise) free((char*)pdu->enterprise);
    pdu->enterprise = nullptr;

    if (!clear_all) return;

    pdu->command = 0;
    pdu->reqid   = 0;
#ifdef _SNMPv3
    pdu->msgid             = 0;
    pdu->maxsize_scopedpdu = 0;
#endif
    pdu->errstat  = 0;
    pdu->errindex = 0;

    pdu->enterprise_length = 0;
    pdu->trap_type         = 0;
    pdu->specific_type     = 0;
    pdu->time              = 0;
}

// free a pdu
void snmp_free_pdu(struct snmp_pdu* pdu)
{
    clear_pdu(pdu); // clear and free content
    free(pdu);      // free up pdu itself
}

// add a null var to a pdu
void snmp_add_var(
    struct snmp_pdu* pdu, oid_t* name, int name_length, SmiVALUE* smival)
{
    struct variable_list* vars = nullptr;

    // if we don't have a vb list ,create one
    if (pdu->variables == nullptr)
    {
        pdu->variables = vars =
            (struct variable_list*)malloc(sizeof(struct variable_list));
        assert(vars != nullptr);
    }
    else
    {
        // we have one, find the end
        vars = pdu->variables;
        while (vars->next_variable) vars = vars->next_variable;

        // create a new one
        vars->next_variable =
            (struct variable_list*)malloc(sizeof(struct variable_list));
        assert(vars->next_variable != nullptr);

        vars = vars->next_variable;
    }

    // add the oid with no data
    vars->next_variable = nullptr;

    // hook in the Oid portion
    vars->name = (oid_t*)malloc(name_length * sizeof(oid_t));
    assert(vars->name != nullptr);

    memcpy((char*)vars->name, (char*)name, name_length * sizeof(oid_t));
    vars->name_length = name_length;

    // hook in the SMI value
    switch (smival->syntax)
    {
        // null , do nothing
    case sNMP_SYNTAX_NULL:
    case sNMP_SYNTAX_NOSUCHOBJECT:
    case sNMP_SYNTAX_NOSUCHINSTANCE:
    case sNMP_SYNTAX_ENDOFMIBVIEW: {
        vars->type       = (unsigned char)smival->syntax;
        vars->val.string = nullptr;
        vars->val_len    = 0;
    }
    break;

        // octects
    case sNMP_SYNTAX_OCTETS:
    case sNMP_SYNTAX_OPAQUE:
    case sNMP_SYNTAX_IPADDR: {
        vars->type = (unsigned char)smival->syntax;
        vars->val.string =
            (unsigned char*)malloc((unsigned)smival->value.string.len);
        vars->val_len = (int)smival->value.string.len;
        memcpy((unsigned char*)vars->val.string,
            (unsigned char*)smival->value.string.ptr,
            (unsigned)smival->value.string.len);
    }
    break;

        // oid
    case sNMP_SYNTAX_OID: {
        vars->type      = (unsigned char)smival->syntax;
        vars->val_len   = (int)smival->value.oid.len * sizeof(oid_t);
        vars->val.objid = (oid_t*)malloc((unsigned)vars->val_len);
        memcpy((uint32_t*)vars->val.objid, (uint32_t*)smival->value.oid.ptr,
            (unsigned)vars->val_len);
    }
    break;

    case sNMP_SYNTAX_TIMETICKS:
    case sNMP_SYNTAX_CNTR32:
    case sNMP_SYNTAX_GAUGE32:
        //    case sNMP_SYNTAX_UINT32:
        {
            SmiINT32 templong = 0;
            vars->type        = (unsigned char)smival->syntax;
            vars->val.integer = (SmiINT32*)malloc(sizeof(SmiINT32));
            vars->val_len     = sizeof(SmiINT32);
            templong          = (SmiINT32)smival->value.uNumber;
            memcpy((SmiINT32*)vars->val.integer, (SmiINT32*)&templong,
                sizeof(SmiINT32));
        }
        break;

    case sNMP_SYNTAX_INT32: {
        SmiINT32 templong = 0;
        vars->type        = (unsigned char)smival->syntax;
        vars->val.integer = (SmiINT32*)malloc(sizeof(SmiINT32));
        vars->val_len     = sizeof(SmiINT32);
        templong          = (SmiINT32)smival->value.sNumber;
        memcpy((SmiINT32*)vars->val.integer, (SmiINT32*)&templong,
            sizeof(SmiINT32));
    }
    break;

        // 64 bit counter
    case sNMP_SYNTAX_CNTR64: {
        vars->type = (unsigned char)smival->syntax;
        vars->val.counter64 =
            (struct counter64*)malloc(sizeof(struct counter64));
        vars->val_len = sizeof(struct counter64);
        memcpy((struct counter64*)vars->val.counter64,
            (SmiLPCNTR64) & (smival->value.hNumber), sizeof(SmiCNTR64));
    }
    break;

    } // end switch
}

// build the authentication, works for v1 or v2c
static unsigned char* snmp_auth_build(unsigned char* data, int* length,
    const SmiINT32 version, const unsigned char* community,
    const int community_len, const int messagelen)
{
    // 5 is 3 octets for version and 2 for community header + len
    // This assumes that community will not be longer than 0x7f chars.
    data = asn_build_sequence(
        data, length, ASN_SEQ_CON, messagelen + community_len + 5);
    if (data == nullptr)
    {
        ASNERROR("buildheader");
        return nullptr;
    }
    data = asn_build_int(data, length, ASN_UNI_PRIM | ASN_INTEGER, &version);
    if (data == nullptr)
    {
        ASNERROR("buildint");
        return nullptr;
    }

    data = asn_build_string(
        data, length, ASN_UNI_PRIM | ASN_OCTET_STR, community, community_len);
    if (data == nullptr)
    {
        ASNERROR("buildstring");
        return nullptr;
    }

    return data;
}

// build a variable binding
unsigned char* snmp_build_var_op(unsigned char* data, oid_t* var_name,
    int* var_name_len, unsigned char var_val_type, int var_val_len,
    unsigned char* var_val, int* listlength)
{
    int                   valueLen = 0;
    Buffer<unsigned char> buffer(MAX_SNMP_PACKET);
    unsigned char*        buffer_pos = buffer.get_ptr();
    int                   bufferLen  = MAX_SNMP_PACKET;

    buffer_pos = asn_build_objid(buffer_pos, &bufferLen,
        ASN_UNI_PRIM | ASN_OBJECT_ID, var_name, *var_name_len);
    if (buffer_pos == nullptr)
    {
        ASNERROR("build_var_op: build_objid failed");
        return nullptr;
    }

    // based on the type...
    switch (var_val_type)
    {
    case ASN_INTEGER:
        if (var_val_len != sizeof(SmiINT32))
        {
            ASNERROR("build_var_op: Illegal size of integer");
            return nullptr;
        }
        buffer_pos = asn_build_int(
            buffer_pos, &bufferLen, var_val_type, (SmiINT32*)var_val);
        break;

    case SMI_GAUGE:
    case SMI_COUNTER:
    case SMI_TIMETICKS:
    case SMI_UINTEGER:
        if (var_val_len != sizeof(SmiUINT32))
        {
            ASNERROR("build_var_op: Illegal size of unsigned integer");
            return nullptr;
        }
        buffer_pos = asn_build_unsigned_int(
            buffer_pos, &bufferLen, var_val_type, (SmiUINT32*)var_val);
        break;

    case SMI_COUNTER64:
        if (var_val_len != sizeof(counter64))
        {
            ASNERROR("build_var_op: Illegal size of counter64");
            return nullptr;
        }
        buffer_pos = asn_build_unsigned_int64(
            buffer_pos, &bufferLen, var_val_type, (struct counter64*)var_val);
        break;

    case ASN_OCTET_STR:
    case SMI_IPADDRESS:
    case SMI_OPAQUE:
    case SMI_NSAP:
        buffer_pos = asn_build_string(
            buffer_pos, &bufferLen, var_val_type, var_val, var_val_len);
        break;

    case ASN_OBJECT_ID:
        buffer_pos = asn_build_objid(buffer_pos, &bufferLen, var_val_type,
            (oid_t*)var_val, var_val_len / sizeof(oid_t));
        break;

    case ASN_NULL:
        buffer_pos = asn_build_null(buffer_pos, &bufferLen, var_val_type);
        break;

    case ASN_BIT_STR:
        buffer_pos = asn_build_bitstring(
            buffer_pos, &bufferLen, var_val_type, var_val, var_val_len);
        break;

    case SNMP_NOSUCHOBJECT:
    case SNMP_NOSUCHINSTANCE:
    case SNMP_ENDOFMIBVIEW:
        buffer_pos = asn_build_null(buffer_pos, &bufferLen, var_val_type);
        break;

    default: ASNERROR("build_var_op: wrong type"); return nullptr;
    }
    if (buffer_pos == nullptr)
    {
        ASNERROR("build_var_op: value build failed");
        return nullptr;
    }

    valueLen = SAFE_INT_CAST(buffer_pos - buffer.get_ptr());

    data = asn_build_sequence(data, listlength, ASN_SEQ_CON, valueLen);

    if (data == nullptr || *listlength < valueLen)
    {
        ASNERROR("build_var_op");
        data = nullptr;
    }
    else
    {
        memcpy(data, buffer.get_ptr(), valueLen);
        data += valueLen;
        (*listlength) -= valueLen;
    }
    return data;
}

unsigned char* build_vb(struct snmp_pdu* pdu, unsigned char* buf, int* buf_len)
{
    Buffer<unsigned char> tmp_buf(MAX_SNMP_PACKET);
    unsigned char*        cp        = tmp_buf.get_ptr();
    struct variable_list* vp        = nullptr;
    int                   vb_length = 0;
    int                   length    = MAX_SNMP_PACKET;

    // build varbinds into packet buffer
    for (vp = pdu->variables; vp; vp = vp->next_variable)
    {
        cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type,
            vp->val_len, (unsigned char*)vp->val.string, &length);
        if (cp == nullptr) return nullptr;
    }
    vb_length = SAFE_INT_CAST(cp - tmp_buf.get_ptr());
    *buf_len -= vb_length;
    if (*buf_len <= 0) return nullptr;

    // encode the length of encoded varbinds into buf
    cp = asn_build_header(buf, buf_len, ASN_SEQ_CON, vb_length);
    if (cp == nullptr) return nullptr;

    // copy varbinds from packet behind header in buf
    memcpy(cp, tmp_buf.get_ptr(), vb_length);

    return (cp + vb_length);
}

unsigned char* build_data_pdu(struct snmp_pdu* pdu, unsigned char* buf,
    int* buf_len, unsigned char* vb_buf, int vb_buf_len)
{
    Buffer<unsigned char> tmp_buf(MAX_SNMP_PACKET);
    unsigned char*        cp          = tmp_buf.get_ptr();
    int                   totallength = 0;
    int                   length      = MAX_SNMP_PACKET;

    // build data of pdu into tmp_buf
    if (pdu->command != TRP_REQ_MSG)
    {
        // request id
        cp = asn_build_int(
            cp, &length, ASN_UNI_PRIM | ASN_INTEGER, &pdu->reqid);
        if (cp == nullptr) return nullptr;

        // error status
        cp = asn_build_int(
            cp, &length, ASN_UNI_PRIM | ASN_INTEGER, &pdu->errstat);
        if (cp == nullptr) return nullptr;

        // error index
        cp = asn_build_int(
            cp, &length, ASN_UNI_PRIM | ASN_INTEGER, &pdu->errindex);
        if (cp == nullptr) return nullptr;
    }
    else
    { // this is a trap message
        // enterprise
        cp = asn_build_objid(cp, &length, ASN_UNI_PRIM | ASN_OBJECT_ID,
            (oid_t*)pdu->enterprise, pdu->enterprise_length);
        if (cp == nullptr) return nullptr;

        // agent-addr ; must be IPADDRESS changed by Frank Fock
        cp = asn_build_string(cp, &length, SMI_IPADDRESS,
            (unsigned char*)&pdu->agent_addr.sin_addr.s_addr,
            sizeof(pdu->agent_addr.sin_addr.s_addr));
        if (cp == nullptr) return nullptr;

        SmiINT32 dummy = pdu->trap_type;
        // generic trap
        cp = asn_build_int(cp, &length, ASN_UNI_PRIM | ASN_INTEGER, &dummy);
        if (cp == nullptr) return nullptr;

        dummy = pdu->specific_type;
        // specific trap
        cp = asn_build_int(cp, &length, ASN_UNI_PRIM | ASN_INTEGER, &dummy);
        if (cp == nullptr) return nullptr;

        // timestamp
        cp = asn_build_unsigned_int(cp, &length, SMI_TIMETICKS, &pdu->time);
        if (cp == nullptr) return nullptr;
    }

    if (length < vb_buf_len) return nullptr;

    // save relative position of varbinds
    int const vb_rel_pos = SAFE_INT_CAST(cp - tmp_buf.get_ptr());
    totallength          = SAFE_INT_CAST(cp - tmp_buf.get_ptr()) + vb_buf_len;

    // build header for datapdu into buf
    cp = asn_build_header(
        buf, buf_len, (unsigned char)pdu->command, totallength);
    if (cp == nullptr) return nullptr;
    if (*buf_len < totallength) return nullptr;

    // copy data behind header
    memcpy(cp, tmp_buf.get_ptr(), totallength - vb_buf_len);
    memcpy((char*)cp + vb_rel_pos, (char*)vb_buf, vb_buf_len);
    *buf_len -= totallength;
    return (cp + totallength);
}

// serialize the pdu
int snmp_build(struct snmp_pdu* pdu, unsigned char* packet, int* out_length,
    const snmp_version version, const unsigned char* community,
    const int community_len)
{
    Buffer<unsigned char> buf(MAX_SNMP_PACKET);
    unsigned char*        cp          = nullptr;
    int                   length      = 0;
    int                   totallength = 0;

    // encode vbs with header into packet
    length = *out_length;
    cp     = build_vb(pdu, packet, &length);
    if (cp == nullptr) return -1;
    totallength = SAFE_INT_CAST(cp - packet);
    if (totallength >= *out_length) return -1;

    // encode datadpu into buf
    length = MAX_SNMP_PACKET;
    cp     = build_data_pdu(pdu, buf.get_ptr(), &length, packet, totallength);
    if (cp == nullptr) return -1;
    totallength = SAFE_INT_CAST(cp - buf.get_ptr());
    if (totallength >= *out_length) return -1;

    // build SNMP header
    length = *out_length;
    cp     = snmp_auth_build(
        packet, &length, version, community, community_len, totallength);
    if (cp == nullptr) return -1;
    if ((*out_length - (cp - packet)) < totallength) return -1;

    // copy data
    memcpy(cp, buf.get_ptr(), totallength);
    totallength += SAFE_INT_CAST(cp - packet);
    *out_length = totallength;

    return 0;
}

// parse the authentication header
static unsigned char* snmp_auth_parse(unsigned char* data, int* length,
    unsigned char* community, int* community_len, SmiINT32* version)
{
    unsigned char type = 0;

    // get the type
    data = asn_parse_header(data, length, &type);
    if (data == nullptr)
    {
        ASNERROR("bad header");
        return nullptr;
    }

    if (type != ASN_SEQ_CON)
    {
        ASNERROR("wrong auth header type");
        return nullptr;
    }

    // get the version
    data = asn_parse_int(data, length, &type, version);
    if (data == nullptr)
    {
        ASNERROR("bad parse of version");
        return nullptr;
    }

    // get the community name
    data = asn_parse_string(data, length, &type, community, community_len);
    if (data == nullptr)
    {
        ASNERROR("bad parse of community");
        return nullptr;
    }

    return (unsigned char*)data;
}

unsigned char* snmp_parse_var_op(
    unsigned char* data,         // IN - pointer to the start of object
    oid_t*         var_name,     // OUT - object id of variable
    int*           var_name_len, // IN/OUT - length of variable name
    unsigned char* var_val_type, // OUT - type of variable (int or octet
                                 // string) (one byte)
    int*            var_val_len, // OUT - length of variable
    unsigned char** var_val, // OUT - pointer to ASN1 encoded value of variable
    int* listlength) // IN/OUT - number of valid bytes left in var_op_list
{
    unsigned char  var_op_type  = 0;
    int            var_op_len   = *listlength;
    unsigned char* var_op_start = data;

    data = asn_parse_header(data, &var_op_len, &var_op_type);
    if (data == nullptr)
    {
        ASNERROR("Error snmp_parse_var_op: 1");
        return nullptr;
    }
    if (var_op_type != ASN_SEQ_CON) return nullptr;
    data = asn_parse_objid(
        data, &var_op_len, &var_op_type, var_name, var_name_len);
    if (data == nullptr)
    {
        ASNERROR("Error snmp_parse_var_op: 2");
        return nullptr;
    }
    if (var_op_type != (ASN_UNI_PRIM | ASN_OBJECT_ID)) return nullptr;
    *var_val = data; /* save pointer to this object */
    /* find out what type of object this is */
    data = asn_parse_header(data, &var_op_len, var_val_type);
    if (data == nullptr)
    {
        ASNERROR("Error snmp_parse_var_op: 3");
        return nullptr;
    }
    if (((uint32_t)var_op_len + (data - var_op_start))
        > (uint32_t)(*listlength))
    {
        ASNERROR("Error snmp_parse_var_op: 4");
        return nullptr;
    }
    *var_val_len = (int)var_op_len;
    data += var_op_len;
    *listlength -= (int)(data - var_op_start);
    return data;
}

int snmp_parse_vb(struct snmp_pdu* pdu, unsigned char*& data, int& data_len)
{
    unsigned char*        var_val = nullptr;
    int                   len     = 0;
    struct variable_list* vp      = nullptr;
    oid_t                 objid[ASN_MAX_NAME_LEN], *op = nullptr;
    unsigned char         type = 0;

    // get the vb list from received data
    data = asn_parse_header(data, &data_len, &type);
    if (data == nullptr) return SNMP_CLASS_ASN1ERROR;
    if (type != ASN_SEQ_CON) return SNMP_CLASS_ASN1ERROR;
    pdu->variables = nullptr;
    while (data_len > 0)
    {
        if (pdu->variables == nullptr)
        {
            pdu->variables = vp =
                (struct variable_list*)malloc(sizeof(struct variable_list));
        }
        else
        {
            vp->next_variable =
                (struct variable_list*)malloc(sizeof(struct variable_list));
            assert(vp->next_variable != nullptr);

            vp = vp->next_variable;
        }
        vp->next_variable = nullptr;
        vp->val.string    = nullptr;
        vp->name          = nullptr;
        vp->name_length   = ASN_MAX_NAME_LEN;
        data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type,
            &vp->val_len, &var_val, &data_len);
        if (data == nullptr) return SNMP_CLASS_ASN1ERROR;
        op = (oid_t*)malloc((unsigned)vp->name_length * sizeof(oid_t));

        memcpy((char*)op, (char*)objid, vp->name_length * sizeof(oid_t));
        vp->name = op;

        len = MAX_SNMP_PACKET;
        switch ((short)vp->type)
        {
        case ASN_INTEGER:
            vp->val.integer = (SmiINT32*)malloc(sizeof(SmiINT32));
            vp->val_len     = sizeof(SmiINT32);
            asn_parse_int(var_val, &len, &vp->type, vp->val.integer);
            break;

        case SMI_COUNTER:
        case SMI_GAUGE:
        case SMI_TIMETICKS:
        case SMI_UINTEGER:
            vp->val.integer = (SmiINT32*)malloc(sizeof(SmiINT32));
            vp->val_len     = sizeof(SmiINT32);
            asn_parse_unsigned_int(var_val, &len, &vp->type, vp->val.integer);
            break;

        case SMI_COUNTER64:
            vp->val.counter64 =
                (struct counter64*)malloc(sizeof(struct counter64));
            vp->val_len = sizeof(struct counter64);
            asn_parse_unsigned_int64(
                var_val, &len, &vp->type, vp->val.counter64);
            break;

        case ASN_OCTET_STR:
        case SMI_IPADDRESS:
        case SMI_OPAQUE:
        case SMI_NSAP:
            vp->val.string = (unsigned char*)malloc((unsigned)vp->val_len);
            asn_parse_string(
                var_val, &len, &vp->type, vp->val.string, &vp->val_len);
            break;

        case ASN_OBJECT_ID:
            vp->val_len = ASN_MAX_NAME_LEN;
            asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
            // vp->val_len *= sizeof(oid_t);
            vp->val.objid =
                (oid_t*)malloc((unsigned)vp->val_len * sizeof(oid_t));

            memcpy((char*)vp->val.objid, (char*)objid,
                vp->val_len * sizeof(oid_t));
            break;

        case SNMP_NOSUCHOBJECT:
        case SNMP_NOSUCHINSTANCE:
        case SNMP_ENDOFMIBVIEW:
        case ASN_NULL: break;

        default: ASNERROR("bad type returned "); return SNMP_CLASS_ASN1ERROR;
        }
    }
    return SNMP_CLASS_SUCCESS;
}

int snmp_parse_data_pdu(snmp_pdu* pdu, unsigned char*& data, int& length)
{
    oid_t         objid[ASN_MAX_NAME_LEN];
    int           four = 4;
    unsigned char type = 0;

    data = asn_parse_header(data, &length, &type);
    if (data == nullptr) return SNMP_CLASS_ASN1ERROR;

    pdu->command = type;

    if (pdu->command != TRP_REQ_MSG)
    {
        // get the rid error status and error index
        data = asn_parse_int(data, &length, &type, &pdu->reqid);
        if (data == nullptr) return SNMP_CLASS_ASN1ERROR;

        data = asn_parse_int(data, &length, &type, &pdu->errstat);
        if (data == nullptr) return SNMP_CLASS_ASN1ERROR;

        data = asn_parse_int(data, &length, &type, &pdu->errindex);
        if (data == nullptr) return SNMP_CLASS_ASN1ERROR;
    }
    else
    { // is a trap

        // get the enterprise
        pdu->enterprise_length = ASN_MAX_NAME_LEN;
        data                   = asn_parse_objid(
            data, &length, &type, objid, &pdu->enterprise_length);
        if (data == nullptr) return SNMP_CLASS_ASN1ERROR;

        pdu->enterprise =
            (oid_t*)malloc(pdu->enterprise_length * sizeof(oid_t));

        memcpy((char*)pdu->enterprise, (char*)objid,
            pdu->enterprise_length * sizeof(oid_t));

        // get source address
        data = asn_parse_string(data, &length, &type,
            (unsigned char*)&pdu->agent_addr.sin_addr.s_addr, &four);
        if (data == nullptr) return SNMP_CLASS_ASN1ERROR;

        // get trap type
        SmiINT32 dummy = 0;
        data           = asn_parse_int(data, &length, &type, &dummy);
        pdu->trap_type = dummy;

        if (data == nullptr) return SNMP_CLASS_ASN1ERROR;

        // trap specific type
        dummy              = 0;
        data               = asn_parse_int(data, &length, &type, &dummy);
        pdu->specific_type = dummy;
        if (data == nullptr) return SNMP_CLASS_ASN1ERROR;

        // timestamp
        data = asn_parse_unsigned_int(data, &length, &type, &pdu->time);
        if (data == nullptr) return SNMP_CLASS_ASN1ERROR;
    }
    return SNMP_CLASS_SUCCESS;
}

// parse a pdu
int snmp_parse(struct snmp_pdu* pdu, unsigned char* data, int data_length,
    unsigned char* community_name, int& community_len,
    snmp_version& spp_version)
{
    SmiINT32 version = -1;

    // authenticates message and returns length if valid
    data = snmp_auth_parse(
        data, &data_length, community_name, &community_len, &version);
    if (data == nullptr) return SNMP_CLASS_ASN1ERROR;

    if (version != SNMP_VERSION_1 && version != SNMP_VERSION_2C)
    {
        ASNERROR("Wrong version");
        return SNMP_CLASS_BADVERSION;
    }

    spp_version = (snmp_version)version;

    int const res = snmp_parse_data_pdu(pdu, data, data_length);
    if (res != SNMP_CLASS_SUCCESS) return res;

    return snmp_parse_vb(pdu, data, data_length);
}

#ifdef _SNMPv3
// Parse the field HeaderData of a SNMPv3 message and return the values.
unsigned char* asn1_parse_header_data(unsigned char* buf, int* buf_len,
    SmiINT32* msg_id, SmiINT32* msg_max_size, unsigned char* msg_flags,
    SmiINT32* msg_security_model)
{
    unsigned char* buf_ptr = buf;
    int            length  = *buf_len;
    unsigned char  type    = 0;

    buf = asn_parse_header(buf, &length, &type);
    if (!buf)
    {
        debugprintf(0, "Parse error in header HeaderData");
        return nullptr;
    }

    if (type != ASN_SEQ_CON)
    {
        debugprintf(0, "wrong type in header of msgHeaderData");
        return nullptr;
    }

    buf = asn_parse_int(buf, &length, &type, msg_id);
    if (!buf)
    {
        debugprintf(0, "Parse error: msg_id");
        return nullptr;
    }

    buf = asn_parse_int(buf, &length, &type, msg_max_size);
    if (!buf)
    {
        debugprintf(0, "Parse error: msg_max_size");
        return nullptr;
    }

    int dummy = 1;
    buf       = asn_parse_string(buf, &length, &type, msg_flags, &dummy);

    if ((dummy != 1) || (!buf))
    {
        debugprintf(0, "Parse error: msg_flags");
        return nullptr;
    }

    buf = asn_parse_int(buf, &length, &type, msg_security_model);
    if (!buf)
    {
        debugprintf(0, "Parse error: msg_security_model");
        return nullptr;
    }

    if (length)
    {
        debugprintf(0, "Parse error: wrong length in header of HeaderData");
        return nullptr;
    }

    debugprintf(3,
        "Parsed HeaderData: globalDataLength(0x%x), msg_id(%ld), "
        "msg_max_size(0x%lx), msg_flags(0x%x), msg_security_model(0x%lx)",
        length, *msg_id, *msg_max_size, *msg_flags, *msg_security_model);

    *buf_len -= SAFE_INT_CAST(buf - buf_ptr);
    return buf;
}

// Encode the given values for the HeaderData into the buffer.
unsigned char* asn1_build_header_data(unsigned char* outBuf, int* maxLength,
    SmiINT32 msgID, SmiINT32 maxMessageSize, unsigned char msgFlags,
    SmiINT32 securityModel)

{
    unsigned char  buf[MAXLENGTH_GLOBALDATA];
    auto*          bufPtr      = (unsigned char*)&buf;
    unsigned char* outBufPtr   = outBuf;
    int            length      = *maxLength;
    int            totalLength = 0;

#    ifdef INVALID_MAXMSGSIZE
    debugprintf(-10, "\nWARNING: Using constant MaxMessageSize!\n");
    maxMessageSize = 65535;
#    endif

    debugprintf(3,
        "Coding msgID(%ld), maxMessageSize(0x%lx), "
        "msgFlags(0x%x), securityModel(0x%lx)",
        msgID, maxMessageSize, msgFlags, securityModel);

    bufPtr =
        asn_build_int(bufPtr, &length, ASN_UNI_PRIM | ASN_INTEGER, &msgID);
    if (bufPtr == nullptr)
    {
        debugprintf(0, "asn_build_header_data: Error coding msgID");
        return nullptr;
    }
    bufPtr = asn_build_int(
        bufPtr, &length, ASN_UNI_PRIM | ASN_INTEGER, &maxMessageSize);
    if (bufPtr == nullptr)
    {
        debugprintf(0, "asn_build_header_data: Error coding maxMessageSize");
        return nullptr;
    }

    bufPtr = asn_build_string(
        bufPtr, &length, ASN_UNI_PRIM | ASN_OCTET_STR, &msgFlags, 1);
    if (bufPtr == nullptr)
    {
        debugprintf(0, "asn_build_header_data: Error coding msgFlags");
        return nullptr;
    }

    bufPtr = asn_build_int(
        bufPtr, &length, ASN_UNI_PRIM | ASN_INTEGER, &securityModel);
    if (bufPtr == nullptr)
    {
        debugprintf(0, "asn_build_header_data: Error coding securityModel");
        return nullptr;
    }

    totalLength = SAFE_INT_CAST(bufPtr - (unsigned char*)&buf);

    debugprintf(3, "Coding sequence (headerdata), length = 0x%x", totalLength);
    outBufPtr =
        asn_build_sequence(outBufPtr, maxLength, ASN_SEQ_CON, totalLength);

    if (outBufPtr == nullptr)
    {
        debugprintf(0, "asn_build_header_data: Error coding seq headerdata");
        return nullptr;
    }

    if (*maxLength < totalLength)
    {
        debugprintf(0, "asn_build_header_data: Length error");
        return nullptr;
    }

    memcpy(outBufPtr, (unsigned char*)&buf, totalLength);
    outBufPtr += totalLength;
    *maxLength -= totalLength;

    debugprintf(21, "bufHeaderData:");
    debughexprintf(21, outBuf, SAFE_INT_CAST(outBufPtr - outBuf));

    return outBufPtr;
}
#endif

// Parse the ScopedPDU and return the encoded values.
unsigned char* asn1_parse_scoped_pdu(unsigned char* scoped_pdu,
    int* scoped_pdu_len, unsigned char* context_engine_id,
    int* context_engine_id_len, unsigned char* context_name,
    int* context_name_len)
{
    unsigned char type = 0;

    scoped_pdu = asn_parse_header(scoped_pdu, scoped_pdu_len, &type);
    if (!scoped_pdu)
    {
        debugprintf(0, "Parse error: Wrong header in scoped_pdu.");
        return nullptr;
    }

    if (type != ASN_SEQ_CON)
    {
        debugprintf(0, "Parse error: Wrong header type in scoped_pdu.");
        return nullptr;
    }

    scoped_pdu = asn_parse_string(scoped_pdu, scoped_pdu_len, &type,
        context_engine_id, context_engine_id_len);
    if (!scoped_pdu)
    {
        debugprintf(0, "Parse error: context_engine_id");
        return nullptr;
    }

    scoped_pdu = asn_parse_string(
        scoped_pdu, scoped_pdu_len, &type, context_name, context_name_len);
    if (!scoped_pdu)
    {
        debugprintf(0, "mpParseScopedPDU: bad parse of context_name");
        return nullptr;
    }

    debugprintf(3,
        "Parsed scoped_pdu: context_engine_id length(0x%x), "
        "context_name length(0x%x)",
        *context_engine_id_len, *context_name_len);

    return scoped_pdu;
}

// Encode the given values for the scopedPDU into the buffer.
unsigned char* asn1_build_scoped_pdu(unsigned char* outBuf, int* max_len,
    unsigned char* contextEngineID, long contextEngineIDLength,
    unsigned char* contextName, long contextNameLength, unsigned char* data,
    long dataLength)
{
    Buffer<unsigned char> buffer(MAX_SNMP_PACKET);
    unsigned char*        bufPtr    = buffer.get_ptr();
    unsigned char*        outBufPtr = outBuf;

    LOG_BEGIN(loggerModuleName, DEBUG_LOG | 10);
    LOG("ASN1: coding (context engine id) (context name)");
    LOG(OctetStr(contextEngineID, contextEngineIDLength).get_printable());
    LOG(OctetStr(contextName, contextNameLength).get_printable());
    LOG_END;

    bufPtr = asn_build_string(bufPtr, max_len, ASN_UNI_PRIM | ASN_OCTET_STR,
        contextEngineID, contextEngineIDLength);
    if (!bufPtr)
    {
        LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
        LOG("ASN1: Error encoding contextEngineID");
        LOG_END;

        return nullptr;
    }

    bufPtr = asn_build_string(bufPtr, max_len, ASN_UNI_PRIM | ASN_OCTET_STR,
        contextName, contextNameLength);
    if (!bufPtr)
    {
        LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
        LOG("ASN1: Error encoding contextName");
        LOG_END;

        return nullptr;
    }

    long bufLength = SAFE_INT_CAST(bufPtr - buffer.get_ptr());

    memcpy((char*)bufPtr, (char*)data, dataLength);
    bufLength += dataLength;

    LOG_BEGIN(loggerModuleName, DEBUG_LOG | 10);
    LOG("ASN1: Encoding scoped PDU sequence (len)");
    LOG(bufLength);
    LOG_END;

    outBufPtr = asn_build_sequence(outBufPtr, max_len, ASN_SEQ_CON, bufLength);
    if (!outBufPtr)
    {
        LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
        LOG("ASN1: Error encoding scopedPDU sequence");
        LOG_END;

        return nullptr;
    }

    memcpy(outBufPtr, buffer.get_ptr(), bufLength);
    outBufPtr += bufLength;

#ifdef __DEBUG
    LOG_BEGIN(loggerModuleName, DEBUG_LOG | 15);
    LOG("ASN1: Result of build_scoped_pdu (len) (data)");
    LOG(outBufPtr - outBuf);
    LOG(OctetStr(outBuf, outBufPtr - outBuf).get_printable_hex());
    LOG_END;
#endif

    return outBufPtr;
}

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif
