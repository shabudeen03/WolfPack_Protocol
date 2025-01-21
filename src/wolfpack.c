#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <assert.h>

#include "wolfpack.h"


void print_packet_sf(const unsigned char *packet) {
    unsigned char *p = &packet[0];

    int counters[8] = {5, 5, 1, 1, 3, 2, 3, 4};
    int count = 0;
    int i = 0;
    
    int totalLen = 0;

    while(p < &packet[24]) { 
        if(i == 6) {
            totalLen = (totalLen << 8) | (unsigned long) *p;
        }
        
        printf("%02x", (unsigned char) *p++);
        count++;

        if(count >= counters[i]) {
            count = 0;
            i++;
            printf("\n");
        }
    }

    totalLen -= 24;

    while(*p != '\0' && totalLen > 0) {
        printf("%c", *p++);
        totalLen--;
    }

    printf("\n");
}

unsigned int checksum_sf(const unsigned char *packet) {
    unsigned char *p = &packet[0];

    unsigned long long sum = 0ULL;
    unsigned long long byte = 0ULL;

    int counters[7] = {5, 5, 1, 1, 3, 2, 3};
    int count = 0;
    int i = 0;

    while(p < &packet[20]) {
        byte = (byte << 8) | (unsigned char) *p++;
        count++;

        if(count >= counters[i]) {
            count = 0;
            i++;
            sum += byte;                    
            byte = 0ULL;
        }
    }

    sum %= (unsigned long) (pow(2, 32) - 1);
    return sum;
}

unsigned int reconstruct_sf(unsigned char *packets[], unsigned int packets_len, char *message, unsigned int message_len) {
    unsigned int counter = 0;
    unsigned int rightMostIdx = 0;

    for(int i=0; i<packets_len; i++) {
        //Byte used to get provided checksum
        unsigned long byte = 0UL;
        for(int j=20; j<24; j++) {
            byte = (byte << 8) | packets[i][j];
        }

        //Compare provided checksum with calculated checksum
        if(byte == checksum_sf(packets[i])) {
            //Byte now used to get fragment offset
            byte = 0;
            for(int j=12; j<15; j++) {
                byte = (byte << 8) | packets[i][j];
            }

            //If valid offset, then use byte now for length of packet
            if(byte >= 0 && byte <= message_len - 2) {
                unsigned int msgIdx = byte;
                counter++;
                byte = 0;
                for(int j=17; j<20; j++) {
                    byte = (byte << 8) | packets[i][j];
                }

                //From just after checksum until length of packet is the payload, write that to message
                for(int j=24; j<byte && msgIdx < message_len - 1; j++) {
                    if(msgIdx > rightMostIdx) {
                        rightMostIdx = msgIdx;
                    }

                    message[msgIdx++] = packets[i][j];
                }
            }
        }
    }

    //Only modify if at least one packet was recovered into message
    if(rightMostIdx > 0) {
        message[rightMostIdx + 1] = '\0';
    }

    return counter;
}

unsigned int packetize_sf(const char *message, unsigned char *packets[], unsigned int packets_len, unsigned int max_payload, unsigned long src_addr, unsigned long dest_addr, unsigned short flags) {
    unsigned int numPackets = 0;
    unsigned int lastPayloadSize = (unsigned int) strlen(message) % max_payload;
    unsigned int payloadSize = max_payload;

    for(int i=0; i<strlen(message) && numPackets < packets_len; i++) {
        unsigned long long byte = 0UL;
        
        if(i >= (strlen(message) - lastPayloadSize)) {
            payloadSize = lastPayloadSize;
        }

        packets[numPackets] = malloc((24 + payloadSize) * sizeof(char));

        //Initialize Addresses
        for(int j=0; j<5; j++) {
            //byte = 0UL;
            byte = (unsigned long) (src_addr >> (8 * (4 - j))) & (unsigned long) 0xff;
            packets[numPackets][j] = byte;

            //byte = 0UL;
            byte = (dest_addr >> (8 * (4 - j))) & (unsigned long) 0xff;
            packets[numPackets][j + 5] = byte;
        }

        //Initialize Ports
        packets[numPackets][10] = 32;
        packets[numPackets][11] = 64;
        
        //Initialize fragment offset
        byte = i;
        for(int j=0; j<3; j++) {
            byte = i >> (8 * (2 - j)) & 0xff;
            packets[numPackets][j + 12] = byte;
        }

        //Initialize Flags
        packets[numPackets][15] = flags >> 8;
        packets[numPackets][16] = flags & 0xff;

        //Initialize total length
        unsigned int len = 24 + payloadSize;
        for(int j=0; j<3; j++) {
            byte = len >> (8 * (2 - j)) & 0xff;
            packets[numPackets][j + 17] = byte;
        }

        //Initialize checksum
        unsigned int checksum = checksum_sf(packets[numPackets]);
        for(int j=0; j<4; j++) {
            byte = checksum >> (8 * (3 - j)) & 0xff;
            packets[numPackets][j + 20] = byte;
        }

        //Initialize payload
        for(int j=0; j<payloadSize; j++) {
            packets[numPackets][24 + j] = (unsigned char) message[j + i];
        }

        i += payloadSize - 1;
        numPackets++;
    }

    return numPackets;
}

// int main() {
//     unsigned char packet[] = "\x00\x00\x00\x30\x39\x00\x00\x01\x09\x3b\x20\x40\x00\x00\x00\x10\x00\x00\x00\x1d\x00\x01\x49\xf1\x41\x42\x43\x44\x45RANDOM GARBAGE YOU SHOULD NOT SEE THIS";

//     print_packet_sf(packet);

//     return 0;
// }