// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  rule.h 
/// Abstract:  simple rule struct type definition
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

#define ANY_STRING "*"
#define ANY_SHORT 0
#define ANY_IP ANY_STRING
#define ANY_PORT ANY_SHORT
#define ANY_PROTO 0

namespace firewall_core {
    struct Rule {
        std::string srcIP;            //source IP in string format
        std::string destIP;           //destination ip in string format
        u_short srcPort;
        u_short destPort;
        u_char proto;
        ndisapi::queued_packet_filter::packet_action action;

        //default contructor
        //set every feild to ANY
        //set action to 'pass'
        Rule() {
            srcIP = ANY_IP, destIP = ANY_IP;
            srcPort = ANY_PORT, destPort = ANY_PORT, proto = ANY_PROTO;
            action = ndisapi::queued_packet_filter::packet_action::pass;
        }

        Rule(u_char proto, std::string srcIP, std::string destIP, short srcPort, short destPort,
            ndisapi::queued_packet_filter::packet_action action = ndisapi::queued_packet_filter::packet_action::pass) {
            this->srcIP = srcIP, this->destIP = destIP;
            this->srcPort = srcPort, this->destPort = destPort, this->proto = proto;
            this->action = action;
        }
    };
}
