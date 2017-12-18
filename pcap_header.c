//
// Created by sleiman on 21/04/17.
//

#include <stdio.h>
#include "pcap_header.h"

pcap_hdr_t *fileHeader;
pcaprec_hdr_t *pcapRecHdr;


void printPCAPHeader(const char *mappedFilePTR, const char * filename, const __off_t fileSize){

    fileHeader = (pcap_hdr_t*)mappedFilePTR;
    printf("Pcap Global Header:\n\n" );
    printf("File: %s\nSize: %zu\nMagic Number: %0X\nEncapsulation: %i\nMax Len: %i\nVersion: %d.%d\nTimezone GMT: %d\n",
           filename, fileSize, fileHeader->magic_number, fileHeader->network, fileHeader->snaplen,
           fileHeader->version_major, fileHeader->version_minor, fileHeader->thiszone
    );

    printf("\n" );

}

void printPCAPHeaderHex(const char *mappedFilePTR){
    char *fileHeaderPtr; /*TO PRINT HEX*/
    fileHeaderPtr = mappedFilePTR;

    printf("Pcap Global Header in Hex:\n");
    for (int i=0; i<24; i++)
        printf("%02X%s", *fileHeaderPtr++ & 0xFF, (i+1) % 16 == 0 ? "\r\n" : " " );

}

void printPCAPRecordHeader(const char *pcapRecHdrPtr){
   // char *pcapRecHdrPtr = mappedFilePPTR + 24; // global header len
    pcapRecHdr = (pcaprec_hdr_t*) pcapRecHdrPtr;
    printf("\nPCAP Rec Header:\n------------\n");
    printf("Capture Time: %d\nMilliseconds: %d\nBytes On Wire: %d\nBytes Captured: %d\n\n" ,
           pcapRecHdr->ts_sec, pcapRecHdr->ts_usec, pcapRecHdr->incl_len, pcapRecHdr->orig_len);
}

void printPCAPRecordHeaderHex(const char *pcapRecHdrPtr){
   // char *pcapRecHdrPtr = mappedFilePPTR + 24; // global header len
    printf("Pcap Record Header in Hex:\n");
    for (int i=0; i<16; i++)
        printf("%02X%s", *pcapRecHdrPtr++ & 0xFF, (i+1) % 16 == 0 ? "\r\n" : " " );

}

uint32_t getPcapRecInclLen(const char *pcapRecHdrPtr){
    pcapRecHdr = (pcaprec_hdr_t*) pcapRecHdrPtr;
    return pcapRecHdr->incl_len;

}
uint32_t getPcapRecOrigLen(const char *pcapRecHdrPtr){
    pcapRecHdr = (pcaprec_hdr_t*) pcapRecHdrPtr;
    return pcapRecHdr->orig_len;
}


