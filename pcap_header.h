//
// Created by sleiman on 21/04/17.
//

#ifndef MYPCAPREADERC_PCAP_HEADER_H
#define MYPCAPREADERC_PCAP_HEADER_H


#include <stdint.h>

#define PCAPGLB_HDR_LEN 24
#define PCAPREC_HDR_LEN 16

// File Header
typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    uint32_t thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;



// Frame Record Header
typedef struct pcaprec_hdr_s {
    uint32_t  ts_sec;         /* timestamp seconds */
    uint32_t  ts_usec;        /* timestamp microseconds */
    uint32_t  incl_len;       /* number of octets of packet saved in file */
    uint32_t  orig_len;       /* actual length of packet */
} pcaprec_hdr_t;


void printPCAPHeader(const char *mappedFilePTR, const char * filename, const __off_t fileSize);
void printPCAPHeaderHex(const char *mappedFilePTR);
void printPCAPRecordHeader(const char *mappedFilePTR);
void printPCAPRecordHeaderHex(const char *mappedFilePTR);
uint32_t getPcapRecInclLen(const char *pcapRecHdrPtr);
uint32_t getPcapRecOrigLen(const char *pcapRecHdrPtr);
uint32_t getPcapRecSeconds(const char *pcapRecHdrPtr);
uint32_t getPcapRecMicroSeconds(const char *pcapRecHdrPtr);



#endif //MYPCAPREADERC_PCAP_HEADER_H
