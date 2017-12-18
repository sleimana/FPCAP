//
// Created by sleiman on 21/04/17.
//

#include <stdint.h>
#include <stdbool.h>


#ifndef MYPCAPREADERC_COMMON_H
#define MYPCAPREADERC_COMMON_H


#define PROTO_IPV4  0X0008
#define PROTO_ARP   0X0608
#define PROTO_RARP  0X3580
#define PROTO_TCP   6


extern uint32_t nIPV4;
extern uint32_t nIPV6;
extern uint32_t nARP;
extern uint32_t nTCP;
extern uint32_t nRARP;
extern uint32_t nNA;
extern uint32_t nPackets;


extern bool SHOW_IP;
extern bool SHOW_TCP;
extern bool SHOW_ARP;
extern bool SHOW_HEX;
extern bool SHOW_ETHER;
extern bool PROCESS_LAYER3;


void tstart();
void tstop();

void printIP(char *sType, char *orig);

void printMac(char *sType, char *orig);

char *getIPStr(char *orig);

void printPacketsInfo(uint16_t proto, char *ptrPcapRecData);

char *openPcapFile(char *fileName);
void printStats();


#endif //MYPCAPREADERC_COMMON_H
