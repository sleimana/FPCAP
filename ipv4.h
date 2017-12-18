//
// Created by sleiman on 19/04/17.
//

#ifndef MYPCAPREADERC_IPV4_H
#define MYPCAPREADERC_IPV4_H

#include <stdint.h>

typedef struct ipv4_s{


    uint8_t ip_hdr_len:4;
    uint8_t ip_version:4;
    uint8_t ip_tos;
    uint16_t ip_totalLength;
    uint16_t ip_identification;
    uint16_t ip_flags:4;
    uint16_t ip_fragOffset:12;
    uint8_t ip_ttl;
    uint8_t ip_proto;
    uint16_t ip_chk;
    uint8_t ip_src[4];
    uint8_t ip_dst[4];

}ipv4_t;

void printIPHeader(char *ptrPcapRecData);

uint8_t getIPToS(ipv4_t *ipPacket);

uint8_t getIPTTL(ipv4_t *ipPacket);

uint16_t getIPTL(ipv4_t *ipPacket);

uint8_t getIPProto(ipv4_t *ipPacket);

uint8_t getIPSRC(ipv4_t *ipPacket);

uint8_t getIPDST(ipv4_t *ipPacket);

uint8_t getIPHDLenBytes(ipv4_t *ipPacket);



#endif //MYPCAPREADERC_IPV4_H
