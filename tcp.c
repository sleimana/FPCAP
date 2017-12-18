//
// Created by sleiman on 21/04/17.
//

#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "tcp.h"

tcp_t *tcpSegement;

void printTCPHeader(char *segmentPtr) {
    printf("TCP Data:\n---------\n");
    tcpSegement = (tcp_t *) segmentPtr;
    printf("TCP SRC Port: %d\nTCP DST Port: %d\nTCP SEQ#: 0x%X\nTCP ACK#: 0x%X\nTCP Offset: %02X\n"
                   "TCP Flags: %s\nTCP Window: %X\nTCP CHK: %X\nTCP Urgent Pointer: %X\n",
           getTCPSrcPort(tcpSegement), getTCPDstPort(tcpSegement),
           getTCPSeqNum(tcpSegement), getTCPAckNum(tcpSegement),
           getTCPOffset(tcpSegement), getTCPFlag(tcpSegement),
           getTCPWindow(tcpSegement), getTCPChecksum(tcpSegement),
           getTCPUrgentPointer(tcpSegement)
    );

    printf("\n");
}

uint16_t getTCPSrcPort(tcp_t *tcpSegemen) {
    return ntohs(tcpSegement->tcp_src_port);
}

uint16_t getTCPDstPort(tcp_t *tcpSegemen) {
    return ntohs(tcpSegement->tcp_dst_port);
}

uint32_t getTCPSeqNum(tcp_t *tcpSegemen) {
    return tcpSegement->sequenceNum;
}

uint32_t getTCPAckNum(tcp_t *tcpSegemen) {
    return tcpSegement->acknowledgeNum;
}

uint8_t getTCPFlags(tcp_t *tcpSegemen) {
    return tcpSegemen->tcp_flags;
}

uint8_t getTCPOffset(tcp_t *tcpSegemen) {
    return tcpSegemen->tcp_offset;
}

uint16_t getTCPWindow(tcp_t *tcpSegemen) {
    return tcpSegemen->tcp_window;
}

uint16_t getTCPChecksum(tcp_t *tcpSegemen) {
    return tcpSegemen->tcp_chk;
}

uint16_t getTCPUrgentPointer(tcp_t *tcpSegemen) {
    return tcpSegemen->tcp_urgptr;
}

char *getTCPFlag(tcp_t *tcpSegemen) {
    char *buffer = malloc(2);

    switch (getTCPFlags(tcpSegemen)) {
        case TCP_FIN:
            return "(FIN)";

        case TCP_SYN:
            return "(SYN)";

        case TCP_FIN_SYN:
            return "(FIN, SYN)";

        case TCP_RST:
            return "(RST)";

        case TCP_PSH:
            return "(PSH)";

        case TCP_FIN_PSH:
            return "(FIN, PSH)";

        case TCP_SYN_PSH:
            return "(SYN, PSH)";

        case TCP_FIN_SYN_PSH:
            return "(FIN, SYN, PSH)";

        case TCP_ACK:
            return "(ACK)";

        case TCP_FIN_ACK:
            return "(FIN, ACK)";

        case TCP_SYN_ACK:
            return "(SYN, ACK)";

        case TCP_FIN_SYN_ACK:
            return ("FIN, SYN, ACK");

        case TCP_PSH_ACK:
            return ("(PSH, ACK)");

        case TCP_URG:
            return "(URG)";

        default:
            snprintf(buffer, sizeof(buffer), "%0X", getTCPFlags(tcpSegemen));
            return buffer;
    }


}