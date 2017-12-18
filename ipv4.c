//
// Created by sleiman on 21/04/17.
//

#include <stdio.h>
#include <netinet/in.h>
#include "ipv4.h"
#include "common.h"
#include "ethernet.h"

ipv4_t *ipPacket;

void printIPHeader(char *ptrPcapRecData) {
    ipPacket = (ipv4_t *) (ptrPcapRecData + ETHERNET_HDR_LEN);
    printf("\nProtocol: IPV4\n--------------\n");
    printf("IP Header Len: %d\n"
                   "IP Version: %X\n"
                   "IP TOS: %02X\n"
                   "IP Total Len: %d\n"
                   "IP Identification: %04X\n"
                   "IP Flags: %02X\n"
                   "IP Fragment Offset: %04X\n"
                   "IP TTL: %d\n"
                   "IP Protocol: %X\n"
                   "IP checksum: %04X\n"
                   "IP Source Address: %s\n",
            /*"IP SRC: %X\nIP DST: %X",*/
           getIPHDLenBytes(ipPacket), ipPacket->ip_version, getIPToS(ipPacket), ntohs(getIPTL(ipPacket)),
           ipPacket->ip_identification,
           ipPacket->ip_flags, ipPacket->ip_fragOffset, getIPTTL(ipPacket), getIPProto(ipPacket), ipPacket->ip_chk,
           getIPStr(ipPacket->ip_src));

    //printIP("IP Source Address: ", ipPacket->ip_src);
    printIP("IP Destination Address: ", ipPacket->ip_dst);
    printf("\n");
}

uint8_t getIPToS(ipv4_t *ipPacket) {
    return ipPacket->ip_tos;
}

uint8_t getIPProto(ipv4_t *ipPacket) {
    return ipPacket->ip_proto;
}

uint8_t getIPTTL(ipv4_t *ipPacket) {
    return ipPacket->ip_ttl;
}

uint16_t getIPTL(ipv4_t *ipPacket) {
    return ipPacket->ip_totalLength;
}

uint8_t getIPHDLenBytes(ipv4_t *ipPacket) {
    return 4 * (ipPacket->ip_hdr_len);
}

uint8_t getIPSRC(ipv4_t *ipPacket) {
    return ipPacket->ip_src;
}

uint8_t getIPDST(ipv4_t *ipPacket) {
    return ipPacket->ip_dst;
}
