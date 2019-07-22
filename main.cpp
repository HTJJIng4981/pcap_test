#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

void check_ip(const u_char * packet);
void check_tcp(const u_char * packet);
void check_tcp_data(const u_char * packet);

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char *packet){
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *packet, *(packet+1), *(packet+2), *(packet+3), *(packet+4), *(packet+5));
}

void print_ip(const u_char *packet){
    printf("%d.%d.%d.%d\n", *packet, *(packet+1), *(packet+2), *(packet+3));
}

void print_port(const u_char *packet){
    printf("%d\n", (*(packet) << 8 ) | *(packet+1));
}

void check_ip(const u_char * packet){
    uint32_t ip= ( ((uint32_t)packet[12] << 8) | ((uint32_t)packet[13]) );
    if( ip == 0x0800)
        check_tcp(packet);
}

void check_tcp(const u_char *packet){
    uint8_t tcp = ( (uint8_t)packet[14 + 9] );
    if( tcp == 0x06 )
        check_tcp_data(packet);
}

void check_tcp_data(const u_char *packet){
    uint8_t tcp_data_size = ( (uint8_t)packet[14 + 2] - 20 - 20 );
    int i=0;
    while(tcp_data_size-- && i != 10){
        printf("%x ", (uint8_t)packet[14 + 20 + 20 + i]);
        i++;
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1]; // argv[1] -> ens33
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // device, recieve size, all, error_msg
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("D-MAC:  ");
    print_mac(packet);
    printf("S-MAC:  ");
    print_mac(packet+6);
    printf("S-ip:   ");
    print_ip(packet+14+12);
    printf("D-ip:   ");
    print_ip(packet+14+16);
    printf("S-Port: ");
    print_port(packet+14+20);
    printf("D-Port: ");
    print_port(packet+14+22);
    check_ip(packet);
   }
  pcap_close(handle);
  return 0;
}
