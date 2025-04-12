// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  packetInformation.h 
/// Abstract:  simple packet information struct definition
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

#define ANY_STRING "*"
#define ANY_SHORT 0
#define ANY_IP ANY_STRING
#define ANY_MAC ANY_STRING
#define ANY_PORT ANY_SHORT
#define ANY_PROTO 0


namespace firewall_core {
    struct PacketInformation {
        std::string packetID;
        std::string srcIP;                //source IP in string format
        std::string destIP;           //destination ip in string format
        std::string srcMAC;               //source MAC in "255:255:255:255:255:255" format
        std::string destMAC;          //destination MAC in "255:255:255:255:255:255" format
        u_short srcPort;
        u_short destPort;
        u_char proto;
        ndisapi::fastio_packet_filter::packet_action action;                    //0->pass   1->drop    2->revert

        PacketInformation() {
            packetID = "-1";
            srcIP = ANY_IP;
            destIP = ANY_IP;
            srcPort = ANY_PORT;
            destPort = ANY_PORT;
            srcMAC = ANY_MAC;
            destMAC = ANY_MAC;
            proto = ANY_PROTO;
            action = ndisapi::fastio_packet_filter::packet_action::pass;
        }
    };
}
/// <summary>
/// 
/// 
/// 
///                   ADNAN's TEMPORARY CODe
/// 
/// 
/// </summary>
/// <param name="buffer"></param>
/// <returns></returns>
/*
PacketInformation extractPacket(INTERMEDIATE_BUFFER& buffer) {
    //returned packet
    PacketInformation packet;

    auto* ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

    //MAC src/des
    packet.sourceMAC = to_string(ethernet_header->h_source[0]) + ":"
        + to_string(ethernet_header->h_source[1]) + ":"
        + to_string(ethernet_header->h_source[2]) + ":"
        + to_string(ethernet_header->h_source[3]) + ":"
        + to_string(ethernet_header->h_source[4]) + ":"
        + to_string(ethernet_header->h_source[5]);

    packet.destinationMAC = to_string(ethernet_header->h_dest[0]) + ":"
        + to_string(ethernet_header->h_dest[1]) + ":"
        + to_string(ethernet_header->h_dest[2]) + ":"
        + to_string(ethernet_header->h_dest[3]) + ":"
        + to_string(ethernet_header->h_dest[4]) + ":"
        + to_string(ethernet_header->h_dest[5]);


    if (ethernet_header->h_proto == ntohs(ETH_P_IP))
    {
        auto* ip_header = reinterpret_cast<iphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header));


        //protocol
        packet.protocol = ip_header->ip_p;


        //src/dest ports
        if (ip_header->ip_p == IPPROTO_TCP)
        {
            auto* tcp_header = reinterpret_cast<tcphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header) + ip_header->ip_hl * 4);
            packet.sourcePort = ntohs(tcp_header->th_sport);
            packet.destinationPort = ntohs(tcp_header->th_dport);
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            auto* udp_header = reinterpret_cast<udphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header) + ip_header->ip_hl * 4);
            packet.sourcePort = ntohs(udp_header->th_sport);
            packet.destinationPort = ntohs(udp_header->th_dport);
        }

        //extract src/dst IPs
        char srcip_str[INET_ADDRSTRLEN]; // Buffer to hold the IP string
        char destip_str[INET_ADDRSTRLEN];
        InetNtopA(AF_INET, &ip_header->ip_src, srcip_str, INET_ADDRSTRLEN); // Converts the IP to a string (ANSI version)
        InetNtopA(AF_INET, &ip_header->ip_dst, destip_str, INET_ADDRSTRLEN);

        packet.sourceIP = srcip_str;
        packet.destinationIP = destip_str;
    }

    return packet;
}
*/