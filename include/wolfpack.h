/* DO NOT CHANGE THIS FILE. IT WILL BE REPLACED DURING GRADING. */

/* Functions to implement */
void print_packet_sf(const unsigned char *packet);
unsigned int checksum_sf(const unsigned char *packet);
unsigned int reconstruct_sf(unsigned char *packets[], unsigned int packets_len, char *message, unsigned int message_len);
unsigned int packetize_sf(const char *message, unsigned char *packets[], unsigned int packets_len, unsigned int max_payload,
    unsigned long src_addr, unsigned long dest_addr, unsigned short flags);