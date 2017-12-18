#include <stdio.h>
#include <zconf.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "ethernet.h"
#include "common.h"
#include "pcap_header.h"


int main(int argc, char *argv[]) {

    unsigned int nPacketsToShow;
    char *mappedFilePtr; // Pointer to the mapped Pcap File
    char *pcapRecHdrPtr; // Pointer to Pcap Record Header
    char *pcapRecDataPtr;// Pointer to Pcap Record Data


    printf("Starting the program...\n");

    if (argc < 2 || argc > 3){
        printf("usage: MyPCAPReaderC filename [number of packets]\n");
        exit(1);
    }

    if (argc == 2) nPacketsToShow = 2; /* If not specified, set the default number of packets t show to 2*/
    else
        nPacketsToShow = (unsigned int) atoi(argv[2]); /* Show the specific number of packets*/

    if (nPacketsToShow == 0) nPacketsToShow = UINT_MAX; /* if set to 0, then show all packets in the file */

    mappedFilePtr = openPcapFile(argv[1]); /* open the file, mmap it, print the header, then return a pointer to it*/

    printf("\n\nGetting infos about the first %i Packet:\n\n", nPacketsToShow );

    pcapRecHdrPtr = mappedFilePtr + PCAPGLB_HDR_LEN;
    pcapRecDataPtr = (pcapRecHdrPtr + PCAPREC_HDR_LEN);

    for (int i=0; i<nPacketsToShow; i++){

        unsigned int lastPcapRecLen;
        lastPcapRecLen = getPcapRecInclLen(pcapRecHdrPtr);
        if(getPcapRecOrigLen(pcapRecHdrPtr) == 0){
            printf("\n\nReached the end of file with [%i] total captured packet\n", i );
            break;
        }

        printf("Packet(%i):\n", i+1);
        printPCAPRecordHeader(pcapRecHdrPtr);

        if (SHOW_ETHER) {
            printEthernetHeader(pcapRecDataPtr);
        }

        if (PROCESS_LAYER3) {
            printPacketsInfo(getEthernetType(pcapRecDataPtr), pcapRecDataPtr);
        }

        if (SHOW_HEX) {
            printPCAPRecordHeaderHex(pcapRecHdrPtr);
            printFrameDataHex(pcapRecDataPtr, 0, lastPcapRecLen);
        }
        printf("\n\n== == == == == == == == == == == == == == == ==\n" );

        pcapRecHdrPtr = pcapRecHdrPtr +PCAPREC_HDR_LEN +lastPcapRecLen;
        pcapRecDataPtr = pcapRecDataPtr +lastPcapRecLen +PCAPREC_HDR_LEN;
        nPackets++;
    }

    tstop();
    printStats();

    return 0;
}

