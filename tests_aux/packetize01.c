#include <stdlib.h>
#include "wolfpack.h"

int main() {
    char msg[] = "ABCDEFGHIJKL";
    unsigned char *packets_act[3];
    unsigned int packets_len = 3;
    unsigned int max_payload = 5;
    unsigned long src_addr = 12345;
    unsigned long dest_addr = 67899;
    unsigned short encryption = 4096;
    unsigned int num_packets_exp = 3;
    packetize_sf(msg, packets_act, packets_len, max_payload, src_addr, dest_addr, encryption);
    for (unsigned int i = 0; i < num_packets_exp; i++)
        free(packets_act[i]);
}