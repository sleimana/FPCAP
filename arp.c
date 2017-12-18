//
// Created by sleiman on 21/04/17.
//


#include <stdio.h>
#include "arp.h"
#include "common.h"
#include "ethernet.h"

arp_t *arpPacket;


void printARPHeader(char *packetPtr){
    printf("\nProtocol: ARP\n-------------\n");
    arpPacket = (arp_t*) (packetPtr +ETHERNET_HDR_LEN);
    printf("HW Type: %04X\nProtocol Type: %04X\nHW Len: %02X\nProto Len: %02X\nOpcode: %04X\n",/*Dst Mac: %s\n",*/
           arpPacket->hardwareType, (arpPacket->protocolType ), arpPacket->hwAdressLength,
           arpPacket->proAddressLegnth, arpPacket->opcode /*"##:##:##:##:##:##"*//* getMac(arpPacket->dstMac)*/);
    printMac("Sender Mac: ", arpPacket->srcMac);
    printMac("Target Mac: ", arpPacket->dstMac);
    printIP("Sender IP: ", arpPacket->senderProtocolAddress);
    printIP("Target IP: ", arpPacket->targetProtocolAddress);
    printf("\n");

}

