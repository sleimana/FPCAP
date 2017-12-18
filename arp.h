//
// Created by sleiman on 08/04/17.
//

#ifndef MYPCAPREADERC_ARP_H
#define MYPCAPREADERC_ARP_H

#include <stdint.h>

typedef struct arp_s{
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hwAdressLength;
    uint8_t proAddressLegnth;
    uint16_t opcode;
    uint8_t srcMac[6];
    uint8_t senderProtocolAddress[4];
    /*uint32_t senderProtocolAddress;*/
    uint8_t dstMac[6];
    uint8_t targetProtocolAddress[4];
} arp_t;

void printARPHeader(char *packetPTR);
#endif //MYPCAPREADERC_ARP_H
