/*____            _        _    ____            _                  
 |  _ \ __ _  ___| | _____| |_ / ___|__ _ _ __ | |_ _   _ _ __ ___ 
 | |_) / _` |/ __| |/ / _ \ __| |   / _` | '_ \| __| | | | '__/ _ \
 |  __/ (_| | (__|   <  __/ |_| |__| (_| | |_) | |_| |_| | | |  __/
 |_|   \__,_|\___|_|\_\___|\__|\____\__,_| .__/ \__|\__,_|_|  \___|
                                         |_|                     
    written by @yeondu1062.
*/

#include <pcap.h>
#include <iostream>
#include <cstdlib>
#include <winsock2.h>
#include <windows.h>

struct IPHDR {
    BYTE verlen;
    BYTE tos;
    WORD len;
    WORD id;
    WORD offset;
    BYTE ttl;
    BYTE protocol;
    WORD checksum;
    ULONG sourceIp;
    ULONG destIp;
};

struct UDPHDR {
    WORD sport;
    WORD dport;
    WORD len;
    WORD checksum;
};
static void setConsoleColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

static void prefixHeader() {
    setConsoleColor(10);
    std::cout << "[PacketCapture] ";
    setConsoleColor(15);
}

static void prefixError() {
    setConsoleColor(12);
    std::cout << "[Error] ";
    setConsoleColor(15);
}

static void handlerPacket(unsigned char* userData, const struct pcap_pkthdr* header, const unsigned char* packet) {
    IPHDR* ipHeader = (IPHDR*)(packet + 14);
    UDPHDR* udpHeader = (UDPHDR*)(packet + 14 + (ipHeader->verlen & 0x0F) * 4);
    ULONG serverIp = ntohl(ipHeader->destIp);

    if (ntohs(udpHeader->sport) != 19132 && ntohs(udpHeader->dport) != 19132) return;
    if (ipHeader->protocol != 0x11) return; //UDP PACKET (0x11)
    if (packet[14 + sizeof(IPHDR) + sizeof(UDPHDR)] != 0x05) return; //ID OPEN CONNECTION REQUEST 1 (0x05)

    prefixHeader();
    std::cout << "세션이 연결되었습니다. (" << (serverIp >> 24) << '.'
        << ((serverIp >> 16) & 0xFF) << '.'
        << ((serverIp >> 8) & 0xFF) << '.'
        << (serverIp & 0xFF) << ")" << std::endl;
}

int main() {
    pcap_t* handle = nullptr;
    pcap_if_t* device = nullptr;
    pcap_if_t* deviceList = nullptr;

    char errMsgBuf[PCAP_ERRBUF_SIZE] = {};

    if (pcap_findalldevs(&deviceList, errMsgBuf) == -1) {
        prefixError();
        std::cerr << "오류가 발생하였습니다: " << errMsgBuf << std::endl;
        return -1;
    }

    if (deviceList == nullptr) {
        prefixError();
        std::cout << "네트워크 장치를 찾지 못하였습니다." << std::endl;
        return -1;
    }

    device = deviceList;
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errMsgBuf);

    prefixHeader();
    std::cout << "마인크래프트 베드락 패킷 캡쳐를 시작합니다.\n선택된 장치: " << device->name << std::endl;

    if (handle == nullptr) {
        prefixError();
        std::cerr << "디바이스를 열지 못하였습니다: " << errMsgBuf << std::endl;
        return -1;
    }

    if (pcap_loop(handle, 0, handlerPacket, nullptr) == -1) {
        prefixError();
        std::cerr << "패킷 캡쳐 중 오류가 발생하였습니다: " << pcap_geterr(handle) << std::endl;
        return -1;
    }

    pcap_close(handle);
    pcap_freealldevs(deviceList);

    return 0;
}
