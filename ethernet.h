//
// Created by sleiman on 05/04/17.
//

#ifndef MYPCAPREADERC_PCAP_FILE_HDR_H
#define MYPCAPREADERC_PCAP_FILE_HDR_H

#include <stdint.h>

#define ETHERNET_HDR_LEN 14
#define MAC_BUFFER_SIZE 18
// Ethernet
typedef struct ethhdr_s{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
} ethhdr_t;

void printEthernetHeader(const char *ptrPcapRecData);

void printFrameDataHex(const char *ptrPcapRecData, unsigned long int startFrame, unsigned long int endFrame);

char *getEtherSrcMacFormatted(ethhdr_t *etherHeader);

char *getEtherDstMacFormatted(ethhdr_t *etherHeader);


uint16_t getEthernetType(const char *ptrPcapRecData);

#endif //MYPCAPREADERC_PCAP_FILE_HDR_H
