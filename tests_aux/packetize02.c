#include <stdlib.h>
#include "wolfpack.h"

int main() {
    char msg[] = "The sight of a dozen patients sitting in the waiting room, each wearing a pained expression, did nothing to lift Harry's mood.";
    unsigned char *packets_act[4];
    unsigned int packets_len = 4;
    unsigned int max_payload = 17;
    unsigned long src_addr = 5000000000L;
    unsigned long dest_addr = 16500000000L;
    unsigned short encryption = 265;
    unsigned int num_packets_exp = 4;
    packetize_sf(msg, packets_act, packets_len, max_payload, src_addr, dest_addr, encryption);
    for (unsigned int i = 0; i < num_packets_exp; i++)
        free(packets_act[i]);
}