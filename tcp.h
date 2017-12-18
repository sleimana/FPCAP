//
// Created by sleiman on 20/04/17.
//

#ifndef MYPCAPREADERC_TCP_H
#define MYPCAPREADERC_TCP_H

#include <stdint.h>

#define TCP_FIN             0x01
#define TCP_SYN             0x02
#define TCP_FIN_SYN         0x03
#define TCP_RST             0x04
#define TCP_PSH             0x08
#define TCP_FIN_PSH         0x09
#define TCP_SYN_PSH         0x0A
#define TCP_FIN_SYN_PSH     0x0B
#define TCP_ACK             0x10
#define TCP_FIN_ACK         0x11
#define TCP_SYN_ACK         0x12
#define TCP_FIN_SYN_ACK     0x13
#define TCP_PSH_ACK         0x18
#define TCP_FIN_PSH_ACK     0x19
#define TCP_SYN_PSH_ACK     0x1A
#define TCP_FIN_SYN_PSH_ACK 0x1B
#define TCP_URG             0x20
#define TCP_ECE     0x40
#define TCP_CWR     0x80

/*
0000 0000 ---
0000 0001 FIN
0000 0010 SYN
0000 0100 RST
0000 1000 PSH
0001 0000 ACK
0010 0000 URG
0100 0000 ECE
1000 0000 CWR
*/

typedef struct tcp_s{

    uint16_t tcp_src_port;
    uint16_t tcp_dst_port;
    uint32_t sequenceNum;
    uint32_t acknowledgeNum;
    uint8_t tcp_offset:4;
    uint8_t tcp_reserved:4;
    uint8_t tcp_flags;
    uint16_t tcp_window;
    uint16_t tcp_chk;
    uint16_t tcp_urgptr;


}tcp_t;

void printTCPHeader(char *segmentPTR);

uint16_t getTCPSrcPort(tcp_t *tcpSegemen);

uint16_t getTCPDstPort(tcp_t *tcpSegemen);

uint32_t getTCPSeqNum(tcp_t *tcpSegemen);

uint32_t getTCPAckNum(tcp_t *tcpSegemen);

uint8_t getTCPOffset(tcp_t *tcpSegemen);

uint8_t getTCPFlags(tcp_t *tcpSegemen);

uint16_t getTCPWindow(tcp_t *tcpSegemen);

uint16_t getTCPChecksum(tcp_t *tcpSegemen);

uint16_t getTCPUrgentPointer(tcp_t *tcpSegemen);

char *getTCPFlag(tcp_t *tcpSegemen);



#endif //MYPCAPREADERC_TCP_H
