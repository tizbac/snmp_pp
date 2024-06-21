/*_############################################################################
 * _##
 * _##  oid.cpp
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
 * purpose. It is provided "AS-IS" without warranty of any kind,either express
 * or implied. User hereby grants a royalty-free license to any and all
 * derivatives based upon this software code base.
 *
 * O I D. C P P
 *
 * OID CLASS IMPLEMENTATION
 *
 * DESIGN + AUTHOR:         Peter E. Mellquist
 *
 * DESCRIPTION:
 * This module contains the implementation of the oid class. This
 * includes all protected and public member functions. The oid class
 * may be compiled stand alone without the use of any other library.
 * =====================================================================*/

#include "snmp_pp/oid.h" // include def for oid class

#include <libsnmp.h>

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp
{
#endif

#define SNMPBUFFSIZE 11 // size of scratch buffer
#define SNMPCHARSIZE 11 // an individual oid instance as a string

//=============[Oid::Oid(const char *dotted_string ]=====================
// constructor using a dotted string
//
// do a string to oid using the string passed in
Oid::Oid(const char* oid_string, const bool is_dotted_oid_string)
    : iv_str(nullptr), iv_part_str(nullptr), m_changed(true)
{
    smival.syntax        = sNMP_SYNTAX_OID;
    smival.value.oid.len = 0;
    smival.value.oid.ptr = nullptr;

    if (is_dotted_oid_string)
    {
        StrToOid(oid_string, &smival.value.oid);
    }
    else
    {
        set_data(oid_string, oid_string ? strlen(oid_string) : 0);
    }
}

//=============[Oid::operator = const char * dotted_string ]==============
// assignment to a string operator overloaded
//
// free the existing oid
// create the new oid from the string
// return this object
Oid& Oid::operator=(const char* dotted_oid_string)
{
    delete_oid_ptr();

    // assign the new value
    StrToOid(dotted_oid_string, &smival.value.oid);
    return *this;
}

//==============[Oid:: operator += const char *a ]=========================
// append operator, appends a string
//
// allocate some space for a max oid string
// extract current string into space
// concat new string
// free up existing oid
// make a new oid from string
// delete allocated space
Oid& Oid::operator+=(const char* a)
{
    size_t n = 0;

    if (!a)
    {
        return *this;
    }

    if (*a == '.')
    {
        ++a;
    }

    n = (smival.value.oid.len * SNMPCHARSIZE) + (smival.value.oid.len) + 1
        + SAFE_UINT_CAST(strlen(a));
    char* ptr = new char[n];
    if (ptr)
    {
        // TODO: optimize this function (use std::string and save result for
        // get_printable() too)! CK
        OidToStr(&smival.value.oid, n, ptr);
        if (ptr[0])
        {
            ::strlcat(ptr, ".", n); // TODO: CWE-119! CK
        }
        ::strlcat(ptr, a, n);       // TODO: CWE-119! CK

        delete_oid_ptr();

        StrToOid(ptr, &smival.value.oid);
        delete[] ptr;
    }
    return *this;
}

//===============[Oid::set_data ]==---=====================================
// copy data from raw form...
void Oid::set_data(const SmiUINT32* raw_oid, const size_t oid_len)
{
    if (smival.value.oid.len < oid_len)
    {
        delete_oid_ptr();

        smival.value.oid.ptr = (SmiLPUINT32) new uint32_t[oid_len];
        if (!smival.value.oid.ptr)
        {
            return;
        }
    }
    memcpy((SmiLPBYTE)smival.value.oid.ptr, (SmiLPBYTE)raw_oid,
        (size_t)(oid_len * sizeof(SmiUINT32)));
    smival.value.oid.len = oid_len;
    m_changed            = true;
}

// Set the data from raw form.
void Oid::set_data(const char* str, const size_t str_len)
{
    if (smival.value.oid.len < str_len)
    {
        delete_oid_ptr();

        smival.value.oid.ptr = (SmiLPUINT32) new uint32_t[str_len];
        if (!smival.value.oid.ptr)
        {
            return;
        }
    }

    if ((!str) || (str_len == 0))
    {
        return;
    }

    for (size_t i = 0; i < str_len; i++)
    {
        smival.value.oid.ptr[i] = (uint32_t)str[i];
    }

    smival.value.oid.len = str_len;
    m_changed            = true;
}

//==============[Oid::get_printable(uint32_t start, n) ]=============
// return a dotted string starting at start,
// going n positions to the left
// NOTE, start is 1 based (the first id is at position #1)
const char* Oid::get_printable(
    const uint32_t start, const uint32_t n, char*& buffer) const
{
    if (!m_changed && (buffer == iv_str))
    {
        return buffer;
    }

    size_t         nz       = 0;
    uint32_t const my_start = start - 1;
    uint32_t const my_end   = my_start + n;

    nz = (smival.value.oid.len * (SNMPCHARSIZE + 1)) + 1;

    if (buffer)
    {
        delete[] buffer;   // delete the previous output string
    }
    buffer = new char[nz]; // allocate some space for the output string
    if (buffer == nullptr)
    {
        return nullptr;
    }

    buffer[0] = 0; // init the string

    // cannot ask for more than there is..
    if ((start == 0) || (my_end > smival.value.oid.len))
    {
        return buffer;
    }

    char* cur_ptr = buffer;
    bool  first   = true;

    // loop through and build up a string
    for (uint32_t index = my_start; index < my_end; ++index)
    {
        // if not at begin, pad with a dot
        if (first)
        {
            first = false;
        }
        else
        {
            *cur_ptr++ = '.';
        }

        // TODO: convert data element to a string, but use std::string! CK
        cur_ptr +=
            snprintf(cur_ptr, nz, "%" PRIu32, smival.value.oid.ptr[index]);
    }

    if (buffer == iv_str)
    {
        Oid* nc_this       = PP_CONST_CAST(Oid*, this);
        nc_this->m_changed = false;
    }

    return buffer;
}

//=============[Oid::StrToOid(char *string, SmiLPOID dst) ]==============
// convert a string to an oid
int Oid::StrToOid(const char* str, SmiLPOID dstOid) const
{
    uint32_t index = 0;

    // make a temp buffer to copy the data into first
    SmiLPUINT32 temp = nullptr;
    uint32_t    nz   = 0;

    if (str && *str)
    {
        nz = SAFE_UINT_CAST(strlen(str));
    }
    else
    {
        dstOid->len = 0;
        dstOid->ptr = nullptr;
        return -1;
    }
    temp = (SmiLPUINT32) new uint32_t[nz];

    if (temp == nullptr)
    {
        return -1; // return if can't get the mem
    }
    while ((*str) && (index < nz))
    {
        // skip over the dot
        if (*str == '.')
        {
            ++str;
        }

        // convert digits
        if (isdigit(*str))
        {
            uint32_t number = 0;

            // grab a digit token and convert it to a int32_t int
            while (isdigit(*str)) { number = (number * 10) + *(str++) - '0'; }

            // stuff the value into the array and bump the counter
            temp[index++] = number;

            // there must be a dot or end of string now
            if ((*str) && (*str != '.'))
            {
                delete[] temp;
                return -1;
            }
        }

        // check for other chars
        if ((*str) && (*str != '.'))
        {
            // found String -> converting it into an oid
            if (*str != '$')
            {
                delete[] temp;
                return -1;
            }

            // skip $
            ++str;

            // copy until second $
            while ((*str) && (*str != '$'))
            {
                temp[index] = (unsigned char)*str;
                ++str;
                ++index;
            }

            if (*str != '$')
            {
                delete[] temp;
                return -1;
            }

            // skip over the $
            ++str;

            // there must be a dot or end of string now
            if ((*str) && (*str != '.'))
            {
                delete[] temp;
                return -1;
            }
        }
    }

    // get some space for the real oid
    dstOid->ptr = (SmiLPUINT32) new uint32_t[index];
    // return if can't get the mem needed
    if (dstOid->ptr == nullptr)
    {
        delete[] temp;
        return -1;
    }

    // copy in the temp data
    memcpy((SmiLPBYTE)dstOid->ptr, (SmiLPBYTE)temp,
        (size_t)(index * sizeof(SmiUINT32)));

    // set the len of the oid
    dstOid->len = index;

    // free up temp data
    delete[] temp;

    return (int)index;
}

//================[Oid::OidToStr ]=========================================
// convert an oid to a string
int Oid::OidToStr(const SmiOID* srcOid, size_t size, char* str) const
{
    unsigned totLen = 0;
    char     szNumber[SNMPBUFFSIZE];

    str[0] = 0; // init the string

    // verify there is something to copy
    if (srcOid->len == 0)
    {
        return -1;
    }

    // loop through and build up a string
    for (uint32_t index = 0; index < srcOid->len; ++index)
    {
        // TODO: convert data element to a string, but use std::string! CK
        int const cur_len = snprintf(
            szNumber, sizeof(szNumber), "%" PRIu32, srcOid->ptr[index]);

        // verify len is not over
        if (totLen + cur_len + 1 >= size)
        {
            return -2;
        }

        // if not at begin, pad with a dot
        if (totLen)
        {
            str[totLen++] = '.';
        }

        // copy the string token into the main string
        ::strlcpy(str + totLen, szNumber, size); // TODO: CWE-119! CK

        // adjust the total len
        totLen += cur_len;
    }
    return totLen + 1;
}

//================[ general Value = operator ]========================
SnmpSyntax& Oid::operator=(const SnmpSyntax& val)
{
    if (this == &val)
    {
        return *this; // protect against assignment from self
    }
    delete_oid_ptr();

    // assign new value
    if (val.valid())
    {
        switch (val.get_syntax())
        {
        case sNMP_SYNTAX_OID: {
            set_data(((Oid&)val).smival.value.oid.ptr,
                (unsigned int)((Oid&)val).smival.value.oid.len);
            break;
        }
        }
    }
    return *this;
}

int Oid::get_asn1_length() const
{
    int length = 1; // for first 2 subids

    for (unsigned int i = 2; i < smival.value.oid.len; ++i)
    {
        uint32_t const v = smival.value.oid.ptr[i];

        if (v < 0x80) //  7 bits long subid
        {
            length += 1;
        }
        else if (v < 0x4000) // 14 bits long subid
        {
            length += 2;
        }
        else if (v < 0x200000) // 21 bits long subid
        {
            length += 3;
        }
        else if (v < 0x10000000) // 28 bits long subid
        {
            length += 4;
        }
        else // 32 bits long subid
        {
            length += 5;
        }
    }

    if (length < 128)
    {
        return length + 2;
    }
    else if (length < 256)
    {
        return length + 3;
    }
    return length + 4;
}

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif
