/*_############################################################################
  _##
  _##  test_app.cpp
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

#include <cstdlib>
#include <iostream>
#include <libsnmp.h>
#include <snmp_pp/snmp_pp.h>
#include <string>

// default request oids
#define NUM_SYS_VBS 6
#define sysDescr    "1.3.6.1.2.1.1.1.0"
#define sysObjectID "1.3.6.1.2.1.1.2.0"
#define sysUpTime   "1.3.6.1.2.1.1.3.0"
#define sysContact  "1.3.6.1.2.1.1.4.0"
#define sysName     "1.3.6.1.2.1.1.5.0"
#define sysLocation "1.3.6.1.2.1.1.6.0"
// XXX #define sysServices	"1.3.6.1.2.1.1.7.0" // not all agents support
// this...

// default notification oid
#define coldStart "1.3.6.1.6.3.1.1.4.3.0.1"

int main(int argc, char** argv)
{
    using namespace Snmp_pp;

    int         status = 0;
    std::string req_str("get");
    // XXX char *dflt_req_oid = (char*) sysDescr;
    const char* dflt_trp_oid = coldStart;
    std::string genAddrStr("127.0.0.1"); // localhost
    std::string oid_str;

    if (argc > 1) genAddrStr = argv[1];
    if (argc > 2) req_str = argv[2];
    if (argc > 3) oid_str = argv[3];

    Snmp::socket_startup(); // Initialize socket subsystem

    UdpAddress ipAddr(genAddrStr.c_str());
    if (!ipAddr.valid())
    {
        std::cerr << "Invalid destination: " << genAddrStr << std::endl;
        exit(EXIT_FAILURE);
    }

    // bind to any port and use IPv6 if needed
    Snmp snmp(status, 0, (ipAddr.get_ip_version() == Address::version_ipv6));
    if (status)
    {
        std::cerr << "Failed to create SNMP Session: " << status << std::endl;
        exit(EXIT_FAILURE);
    }
    std::cout << "Created session successfully" << std::endl;

    ipAddr.set_port(4700);
    CTarget target(ipAddr);
    if (!target.valid())
    {
        std::cerr << "Invalid target" << std::endl;
        exit(EXIT_FAILURE);
    }

    Pdu pdu;
    Vb  vb;
    if (req_str == "get")
    {
        Vb vbl[NUM_SYS_VBS];
        vbl[0].set_oid(sysDescr);
        vbl[1].set_oid(sysObjectID);
        vbl[2].set_oid(sysUpTime);
        vbl[3].set_oid(sysContact);
        vbl[4].set_oid(sysName);
        vbl[5].set_oid(sysLocation);
        // XXX vbl[6].set_oid(sysServices);

        std::cout << "Send a GET-REQUEST to: " << ipAddr.get_printable()
                  << std::endl;
        if (oid_str.empty())
        {
            if ((genAddrStr == "localhost") || (genAddrStr == "127.0.0.1"))
            {
                pdu.set_vblist(vbl, NUM_SYS_VBS);
            }
            else
            {
                for (int i = 0; i < NUM_SYS_VBS; i++) pdu += vbl[i];
            }
        }
        else
        {
            Oid req_oid(oid_str.c_str());
            if (!req_oid.valid())
            {
                std::cerr << "Request oid constructor failed for:" << oid_str
                          << std::endl;
                exit(EXIT_FAILURE);
            }
            vb.set_oid(req_oid);
            pdu += vb;
        }

        status = snmp.get(pdu, target);
        if (status)
        {
            std::cout << "Failed to issue SNMP Get: (" << status << ") "
                      << snmp.error_msg(status) << std::endl;
            exit(EXIT_FAILURE);
        }
        else
        {
            std::cout << "Issued get successfully" << std::endl;
            int vbcount = pdu.get_vb_count();
            if (vbcount == NUM_SYS_VBS)
            {
                pdu.get_vblist(vbl, vbcount);
                for (int i = 0; i < vbcount; i++)
                {
                    std::cout << vbl[i].get_printable_oid() << " : "
                              << vbl[i].get_printable_value() << std::endl;
                }
            }
            else
            {
                for (int i = 0; i < vbcount; i++)
                {
                    pdu.get_vb(vb, i);
                    std::cout << vb.get_printable_oid() << " : "
                              << vb.get_printable_value() << std::endl;
                }
            }
        }
    }
    else if (req_str == "trap")
    {
        std::cout << "Send a TRAP to: " << ipAddr.get_printable() << std::endl;

        if (oid_str.empty()) oid_str = dflt_trp_oid;

        Oid notify_oid(oid_str.c_str());
        if (!notify_oid.valid())
        {
            std::cerr << "Notify oid constructor failed for:" << oid_str
                      << std::endl;
            exit(EXIT_FAILURE);
        }

        pdu.set_notify_id(notify_oid);

        // Use a simple payload
        vb.set_oid(sysLocation);
        vb.set_value("This is a test");
        pdu += vb;

        status = snmp.trap(pdu, target);
        if (status)
        {
            std::cerr << "Failed to issue SNMP Trap: (" << status << ") "
                      << snmp.error_msg(status) << std::endl;
            exit(EXIT_FAILURE);
        }
        else
        {
            std::cout << "Success" << std::endl;
        }
    }
    else
    {
        std::cerr << "Invalid SNMP operation: " << req_str << std::endl;
        std::cerr << "Usage: " << argv[0] << " hostname [[get | trap] OID]"
                  << std::endl;
        exit(EXIT_FAILURE);
    }

    Snmp::socket_cleanup(); // Shut down socket subsystem

    return 0;
}
