#include "pch.h"
#include <iostream>
#include <string>
#include <fstream>     // For file stream
#include <ws2tcpip.h>  // For InetNtopA
#include <iomanip>     // For formatting MAC address output
#include <queue>
#include <mutex>
#include <condition_variable>
using namespace std;


queue<firewall_core::PacketInformation> incoming;
queue<firewall_core::PacketInformation> results;

queue<pair<INTERMEDIATE_BUFFER, u_short>> incoming_queue;
queue<INTERMEDIATE_BUFFER> outgoing_queue;
mutex in_mutex, out_mutex, cout_mutex;
condition_variable in_cv, out_cv;
bool stop_threads = false;

ofstream incoming_file("incoming.txt");
ofstream outgoing_file("outgoing.txt");


//Possible filter actions
const ndisapi::queued_packet_filter::packet_action actions[3] = { ndisapi::queued_packet_filter::packet_action::pass, ndisapi::queued_packet_filter::packet_action::drop, ndisapi::queued_packet_filter::packet_action::revert };

//Adnan's helper function to write packet information into incoming file
void WriteIntoFile(const firewall_core::PacketInformation& p, ofstream& file_stream, u_short ruleID);

// Helper function to write MAC addresses to a file
void write_info_to_file(const string direction, const uint8_t* srcmac, const uint8_t* destmac, const in_addr& srcip, const in_addr& destip, ofstream& file_stream);


//Function to write packet bytes
void write_buffer_hex(const uint8_t* buffer, size_t length, ofstream& file_stream);


//Function to filter packets
ndisapi::queued_packet_filter::packet_action filter(INTERMEDIATE_BUFFER buffer, ether_header_ptr eth_header);


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
firewall_core::PacketInformation extractPacket(INTERMEDIATE_BUFFER& buffer) {
    //returned packet
    firewall_core::PacketInformation packet;

    auto* ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

    //MAC src/des
    packet.srcMAC = to_string(ethernet_header->h_source[0]) + ":"
        + to_string(ethernet_header->h_source[1]) + ":"
        + to_string(ethernet_header->h_source[2]) + ":"
        + to_string(ethernet_header->h_source[3]) + ":"
        + to_string(ethernet_header->h_source[4]) + ":"
        + to_string(ethernet_header->h_source[5]);

    packet.destMAC = to_string(ethernet_header->h_dest[0]) + ":"
        + to_string(ethernet_header->h_dest[1]) + ":"
        + to_string(ethernet_header->h_dest[2]) + ":"
        + to_string(ethernet_header->h_dest[3]) + ":"
        + to_string(ethernet_header->h_dest[4]) + ":"
        + to_string(ethernet_header->h_dest[5]);


    if (ethernet_header->h_proto == ntohs(ETH_P_IP))
    {
        auto* ip_header = reinterpret_cast<iphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header));


        //protocol
        packet.proto = ip_header->ip_p;


        //src/dest ports
        if (ip_header->ip_p == IPPROTO_TCP)
        {
            auto* tcp_header = reinterpret_cast<tcphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header) + ip_header->ip_hl * 4);
            packet.srcPort = ntohs(tcp_header->th_sport);
            packet.destPort = ntohs(tcp_header->th_dport);
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            auto* udp_header = reinterpret_cast<udphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header) + ip_header->ip_hl * 4);
            packet.srcPort = ntohs(udp_header->th_sport);
            packet.destPort = ntohs(udp_header->th_dport);
        }

        //extract src/dst IPs
        char srcip_str[INET_ADDRSTRLEN]; // Buffer to hold the IP string
        char destip_str[INET_ADDRSTRLEN];
        InetNtopA(AF_INET, &ip_header->ip_src, srcip_str, INET_ADDRSTRLEN); // Converts the IP to a string (ANSI version)
        InetNtopA(AF_INET, &ip_header->ip_dst, destip_str, INET_ADDRSTRLEN);

        packet.srcIP = srcip_str;
        packet.destIP = destip_str;
    }

    return packet;
}


/// <summary>
/// 
/// 
/// 
///                             ADNAN's TEMPORARY CODE     
/// 
/// 
/// 
/// </summary>
void incoming_packet_processor()
{
    while (!stop_threads)
    {
        unique_lock<mutex> lock(in_mutex);
        in_cv.wait(lock, [] { return !incoming_queue.empty() || stop_threads; });

        while (!incoming_queue.empty())
        {
            INTERMEDIATE_BUFFER buffer = incoming_queue.front().first;
            u_short ruleID = incoming_queue.front().second;
            incoming_queue.pop();
            lock.unlock();  // Release lock while processing
            
            
            ///////////////////////////////////////////////DEBUGGING/////////////////////////////////
            cout_mutex.lock();
            for (int i = 0; i < buffer.m_Length; i++) {
                cout << hex << setw(2) << setfill('0')
                    << static_cast<int>(buffer.m_IBuffer[i]) << " ";
                
            }
            cout << "\nincoming DONE\n";
            cout << "\n\n\n";
            cout_mutex.unlock();

            firewall_core::PacketInformation p = extractPacket(buffer);
            
            WriteIntoFile(p, incoming_file, ruleID);
            ////////////////////////////////////////////////////////////////////////////////////////


            write_buffer_hex(buffer.m_IBuffer, buffer.m_Length, incoming_file);

            lock.lock();  // Re-acquire lock for the next packet
        }
    }
}

void outgoing_packet_processor()
{
    while (!stop_threads)
    {
        unique_lock<mutex> lock(out_mutex);
        out_cv.wait(lock, [] { return !outgoing_queue.empty() || stop_threads; });

        while (!outgoing_queue.empty())
        {
            INTERMEDIATE_BUFFER buffer = outgoing_queue.front();
            outgoing_queue.pop();
            lock.unlock();  // Release lock while processing

            ///////////////////////////////////////////////DEBUGGING/////////////////////////////////
            cout_mutex.lock();
            for (int i = 0; i < buffer.m_Length; i++) {
                cout << hex << setw(2) << setfill('0')
                    << static_cast<int>(buffer.m_IBuffer[i]) << " ";

            }
            cout << "\noutgoing DONE\n";
            cout << "\n\n\n";
            cout_mutex.unlock();

            firewall_core::PacketInformation p = extractPacket(buffer);

            WriteIntoFile(p, outgoing_file, 0);

            write_buffer_hex(buffer.m_IBuffer, buffer.m_Length, outgoing_file);

            lock.lock();  // Re-acquire lock for the next packet
        }
    }
}

ndisapi::queued_packet_filter::packet_action prcIncoming(HANDLE, INTERMEDIATE_BUFFER& buffer) {
    {
        lock_guard<mutex> lock(in_mutex);
        incoming_queue.push({ buffer, 0 });
    }
    in_cv.notify_one();
    return actions[0];
}

ndisapi::queued_packet_filter::packet_action prcOutgoing(HANDLE, INTERMEDIATE_BUFFER& buffer) {
    {
        lock_guard<mutex> lock(out_mutex);
        outgoing_queue.push(buffer);
    }
    out_cv.notify_one();
    return actions[0];
}

//Firewall Main Component
//auto ndis_api = make_unique<ndisapi::fastio_packet_filter>(prcIncoming,prcOutgoing, true);

firewall_core::RuleExecuter ruleExe;

int main()
{
    cout << "NEW FILE STRUCTURE\n";
    ruleExe.printExe();
    cout << "done\n";

    //Firewall Main Component

    auto ndis_api = make_unique<ndisapi::queued_packet_filter>(
        [](HANDLE, INTERMEDIATE_BUFFER& buffer) {
            
            pair<ndisapi::queued_packet_filter::packet_action, u_short> ans = ruleExe.matchRules(extractPacket(buffer));
            
            {
                lock_guard<mutex> lock(in_mutex);
                incoming_queue.push({ buffer, ans.second });
            }
            in_cv.notify_one();

            return ans.first;
        }, 
        [](HANDLE, INTERMEDIATE_BUFFER& buffer) {
            {
                lock_guard<mutex> lock(out_mutex);
                outgoing_queue.push(buffer);
            }
            out_cv.notify_one();
            return ruleExe.matchRules(extractPacket(buffer)).first;
        });

    try
    {
        // Open file to write info
        if (!incoming_file.is_open() || !outgoing_file.is_open())
        {
            cerr << "Failed to open file for writing IP addresses." << endl;
            return 1;
        }

        thread incoming_thread(incoming_packet_processor);
        thread outgoing_thread(outgoing_packet_processor);



        if (ndis_api->IsDriverLoaded())
        {
            cout << "WinpkFilter is loaded" << endl << endl;
        }
        else
        {
            cout << "WinpkFilter is not loaded" << endl << endl;
            return 1;
        }


        cout << "Available network interfaces:" << endl << endl;
        size_t index = 0;
        for (auto& e : ndis_api->get_interface_names_list())
        {
            cout << ++index << ")\t" << e << endl;
        }

        cout << endl << "Select interface to filter:";
        cin >> index;

        if (index > ndis_api->get_interface_names_list().size())
        {
            cout << "Wrong parameter was selected. Out of range." << endl;
            return 0;
        }


        ndis_api->start_filter(index - 1);

        cout << "Press any key to stop filtering" << endl;

        ignore = _getch();

        cout << "Exiting..." << endl;

        stop_threads = true;
        in_cv.notify_all();
        out_cv.notify_all();
        incoming_thread.join();
        outgoing_thread.join();

        // Close the output file when done
        incoming_file.close();
        outgoing_file.close();

        cin.ignore(); cin.get();

    }
    catch (const exception& ex)
    {
        cout << "Exception occurred: " << ex.what() << endl;
    }

    return 0;
}

void WriteIntoFile(const firewall_core::PacketInformation& p, ofstream& file_stream, u_short ruleID) {
    //Write Protocol
    file_stream << "Protocol: ";
    file_stream << (int)p.proto << endl;

    //Write MAC addresses
    file_stream << "Src MAC: ";
    file_stream << p.srcMAC << endl;

    file_stream << "Dest MAC: ";
    file_stream << p.destMAC << endl;

    file_stream << endl;
    //End of write MAC


    file_stream << "Src IP: " << p.srcIP << endl << "Dest IP: " << p.destIP << endl << endl; // Write IP to file
    //End of write IP

    //write ports;
    file_stream << "Src Port: " << p.srcPort << endl << "Dest Port: " << p.destPort << endl;
    file_stream << "rule id: " << ruleID << endl << endl;
}

void write_info_to_file(const string direction, const uint8_t* srcmac, const uint8_t* destmac, const in_addr& srcip, const in_addr& destip, ofstream& file_stream)
{
    //Write MAC addresses
    file_stream << direction << endl << "Src MAC: ";

    for (int i = 0; i < 6; ++i)
    {
        file_stream << hex << setw(2) << setfill('0') << static_cast<int>(srcmac[i]);
        if (i < 5) file_stream << ":";
    }

    file_stream << endl << "Dest MAC: ";
    for (int i = 0; i < 6; ++i)
    {
        file_stream << hex << setw(2) << setfill('0') << static_cast<int>(destmac[i]);
        if (i < 5) file_stream << ":";
    }
    file_stream << endl;
    //End of write MAC


    //Write IP addresses
    char srcip_str[INET_ADDRSTRLEN]; // Buffer to hold the IP string
    char destip_str[INET_ADDRSTRLEN];
    InetNtopA(AF_INET, &srcip, srcip_str, INET_ADDRSTRLEN); // Converts the IP to a string (ANSI version)
    InetNtopA(AF_INET, &destip, destip_str, INET_ADDRSTRLEN);

    file_stream << "Src IP: " << srcip_str << endl << "Dest IP: " << destip_str << endl << endl; // Write IP to file
    //End of write IP
}




void write_buffer_hex(const uint8_t* buffer, size_t length, ofstream& file_stream)
{
    for (size_t i = 0; i < length; ++i)
    {
        if (i % 32 == 0) file_stream << endl; // New line every 16 bytes
        file_stream << hex << setw(2) << setfill('0')
            << static_cast<int>(buffer[i]) << " ";
    }
    file_stream << dec << endl << endl << endl; // Reset to decimal output
}


ndisapi::queued_packet_filter::packet_action filter(INTERMEDIATE_BUFFER buffer, ether_header_ptr eth_header)
{

    if (eth_header->h_proto == ntohs(ETH_P_IP))
    {
        auto* ip_header = reinterpret_cast<iphdr_ptr>(buffer.m_IBuffer + sizeof(ether_header));

        if (static_cast<int>(ip_header->ip_p) == IPPROTO_ICMP)
            return actions[0];
        else
            return actions[1];
    }
    else if (eth_header->h_proto == ntohs(ETH_P_ARP))
        return actions[0];

    return actions[0];

}
