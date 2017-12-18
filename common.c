//
// Created by sleiman on 21/04/17.
//

#include <stdio.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "common.h"
#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "arp.h"
#include "pcap_header.h"

static struct timeval tm1, tm2;

struct stat sbuf;
__off_t pcapFileSize;
char *mappedFilePtr;


uint32_t nIPV4 = 0;
uint32_t nARP = 0;
uint32_t nTCP = 0;
uint32_t nIPV6 = 0;
uint32_t nRARP = 0;
uint32_t nNA = 0;
uint32_t nPackets = 0;


bool SHOW_IP = 1;
bool SHOW_TCP = 0;
bool SHOW_ARP = 0;
bool SHOW_HEX = 0;
bool SHOW_ETHER = 0;
bool PROCESS_LAYER3 = 1;

char *segmentPTR;
ipv4_t *ipPacket;


void tstart() {
    gettimeofday(&tm1, NULL);
}

void tstop(){
    gettimeofday(&tm2, NULL);
    unsigned long long t = (unsigned long long) 1000 * (tm2.tv_sec - tm1.tv_sec) + (tm2.tv_usec - tm1.tv_usec) / 1000;
    printf("\nPerformed in %llu ms\n", t);
}


char *openPcapFile(char *fileName) {
    int fd;

    printf("Opening the file...\n");

    fd = open(fileName, O_RDONLY);

    if (fd ==-1){
        printf("Error#1 Opening file\n");
        exit(1);
    }

    if (stat(fileName, &sbuf)== -1){
        printf("Error#2 File Stat\n");
        exit(1);
    }

    //check if isPcap()

    pcapFileSize = sbuf.st_size;

    tstart();


    //printf("Mapping...\n" );
    mappedFilePtr = mmap((caddr_t)0, pcapFileSize, PROT_READ, MAP_SHARED, fd, 0);

    if (mappedFilePtr == MAP_FAILED){
        printf("Error#3 mmapping failed\n");
        exit(1);
    }

    /*PRINT_FILE_GLOBAL_HEADER*/
    printPCAPHeader(mappedFilePtr, fileName, pcapFileSize);

    if (SHOW_HEX) {
        printPCAPHeaderHex(mappedFilePtr);
    }

    return mappedFilePtr;

}

void printIP(char *sType, char *orig) {
    printf("%s%u.%u.%u.%u\n", sType,
           (unsigned int)  orig[0] & 0xff, (unsigned int)orig[1] & 0xff,(unsigned int) orig[2] & 0xff,
           (unsigned int) orig[3] & 0xff);
}

char *getIPStr(char *orig) {
    char *buffer = malloc(16);
    int i;
    i = snprintf(buffer, 16, "%u.%u.%u.%u",
                 (unsigned int) orig[0] & 0xff, (unsigned int) orig[1] & 0xff, (unsigned int) orig[2] & 0xff,
                 (unsigned int) orig[3] & 0xff);
    if (i > 6 | i < 15)
        return buffer;
    else
        return "";

}


void printMac(char *sType, char *orig) {
    printf("%s%02X:%02X:%02X:%02X:%02X:%02X\n", sType,
           orig[0] & 0xff, orig[1] & 0xff, orig[2] & 0xff,
           orig[3] & 0xff, orig[4] & 0xff, orig[5] & 0xff);
}

void printPacketsInfo(uint16_t proto, char *ptrPcapRecData) {
    switch(proto){

        case PROTO_IPV4: /*IP PACKET*/
            ipPacket = (ipv4_t*) (ptrPcapRecData +ETHERNET_HDR_LEN);
            if (SHOW_IP) {
                printIPHeader(ptrPcapRecData); /* To-Do PASS THE IP-PACKET DIRECTLY! */
            }
            segmentPTR = ptrPcapRecData + ETHERNET_HDR_LEN +
                         getIPHDLenBytes(ipPacket); /*ipPacket->ip_hdr_len convert to decimal*/;
            if (ipPacket->ip_proto == PROTO_TCP) {
                if (SHOW_TCP) {
                    printTCPHeader(segmentPTR);
                }
                nTCP++;
            }
            nIPV4++;
            break;

        case PROTO_ARP: /*ARP PACKET*/
            if (SHOW_ARP) {
                printARPHeader(ptrPcapRecData);
            }
            //cARP++;
            nARP++;
            break;

        case PROTO_RARP:
            printf("Protocol: RARP\n");
            nRARP++;
            break;

        case 0xDD86: printf("Protocol: IPV6\n");
            nIPV6++;
            break;

        default: {
            printf("N/A\n");
            nNA++;
        }

    }
}

void printStats(){
    printf("\n-----------------\nTotal Packets: %i\n-----------------\n",nPackets);
    printf("IPV4 Packets: %i\nTCP Segments: %i\nIPV6 Packets: %i\nARP  Packets: %i\nRARP Packets: %i\nNot Assigned: %i\n-----------------\n",
           nIPV4, nTCP, nIPV6, nARP, nRARP, nNA);
}






/*
 *
 * char *getMac(char *orig){

    char *out = NULL;// = "##:##:##:##:##:##";
    snprintf(out,18,"%02X:%02X:%02X:%02X:%02X:%02X",
            orig[0] & 0xff, orig[1] & 0xff, orig[2] & 0xff,
            orig[3] & 0xff, orig[4] & 0xff, orig[5] & 0xff);
    return out;

}

unsigned long int convertToInt(char *str) {
    //unsigned long int x;
    return strtol(str, &ptrDummyEnd, 10);

}*/
