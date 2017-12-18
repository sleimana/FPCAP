//
// Created by sleiman on 21/04/17.
//

#include <stdio.h>
#include <stdlib.h>
#include "ethernet.h"
#include "common.h"

ethhdr_t *etherHeader;


void printEthernetHeader(const char *ptrPcapRecData) {

    printf("\nEthernet Data:\n--------------\n" );
    etherHeader = (ethhdr_t *) ptrPcapRecData;
    printf("SRC MAC: %s\n", getEtherSrcMacFormatted(etherHeader));
    printf("DST MAC: %s\n", getEtherDstMacFormatted(etherHeader));
    //printMac("SRC Mac: ", etherHeader->smac);
    //printMac("DST Mac: ", etherHeader->dmac);

    //printf("SRC MAC 2: %X\n",  gerEtherSrcAddress(etherHeader));
    printf("\n");
}

void printFrameDataHex(const char *ptrPcapRecData, unsigned long int startFrame, unsigned long int endFrame) {
    printf("Payload in Hex:\n");
    for (int i=startFrame; i<endFrame; i++)
        printf("%02X%s", *ptrPcapRecData++ & 0xFF, (i+1) % 16 == 0 ? "\r\n" : " " );
}

char *getEtherSrcMacFormatted(ethhdr_t *etherHeader) {
    char *orig = etherHeader->smac;
    char *MacBuffer = malloc(MAC_BUFFER_SIZE);
    snprintf(MacBuffer, MAC_BUFFER_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
             orig[0] & 0xff, orig[1] & 0xff, orig[2] & 0xff,
             orig[3] & 0xff, orig[4] & 0xff, orig[5] & 0xff);
    return MacBuffer;

}

char *getEtherDstMacFormatted(ethhdr_t *etherHeader) {
    char *orig = etherHeader->dmac;
    char *MacBuffer = malloc(MAC_BUFFER_SIZE);
    snprintf(MacBuffer, MAC_BUFFER_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
             orig[0] & 0xff, orig[1] & 0xff, orig[2] & 0xff,
             orig[3] & 0xff, orig[4] & 0xff, orig[5] & 0xff);
    return MacBuffer;
}


uint16_t getEthernetType(const char *ptrPcapRecData) {
    etherHeader = (ethhdr_t *) ptrPcapRecData;
    return etherHeader->type;

}