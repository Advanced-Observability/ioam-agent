#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>

#define IPV6_TLV_IOAM 49
#define IOAM_DEX 4

void print_ip6_address(struct in6_addr *addr) {
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN);
    printf("Received with source IP Address: %s\n", str);
}


void loopback(const struct ip6_hdr *orig_ipv6_hdr) {
    

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("lo", 65536, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device\n", errbuf);
        return;
    }

    char buffer[128]; // Adjust buffer size as needed
    struct ip6_hdr *ipv6_header;
    struct sockaddr_in6 dest_addr;

    // Zero out the buffer and set the IPv6 header
    memset(buffer, 0, sizeof(buffer));
    ipv6_header = (struct ip6_hdr *)buffer;
    ipv6_header->ip6_flow = 0;
    ipv6_header->ip6_plen = htons(0); // No payload in this example
    ipv6_header->ip6_nxt = IPPROTO_NONE; // No next header
    ipv6_header->ip6_hlim = 255; // Hop limit
    ipv6_header->ip6_src = orig_ipv6_hdr->ip6_dst;
    ipv6_header->ip6_dst = orig_ipv6_hdr->ip6_src;

    // Send the packet using pcap_sendpacket
    if (pcap_sendpacket(handle, (const u_char *)buffer, sizeof(struct ip6_hdr)) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
    }
}

void cringe_loopback(const u_char *packet) {
char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("lo", 65536, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device\n", errbuf);
        return;
    }

    // Send the packet using pcap_sendpacket
    if (pcap_sendpacket(handle, packet, 256) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
    }
}


void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet + 14); // Skip Ethernet header
    pcap_t *handle = (pcap_t *)user;

    printf("nxtHdr: %d\n", ipv6_header->ip6_nxt);

    // Check if the next header field matches the Hop-by-Hop Options header
    if (ipv6_header->ip6_nxt == IPPROTO_HOPOPTS) {
        // Parse the Hop-by-Hop Options header
        struct ip6_hbh *hbh_header = (struct ip6_hbh *)(packet + 14 + sizeof(struct ip6_hdr));
        uint8_t hbh_len = (hbh_header->ip6h_len + 1) * 8;

        if (hbh_len > 0) {
            struct ip6_opt *option_hdr = (struct ip6_opt *)(hbh_header + sizeof(struct ip6_hbh));
            uint8_t ip6opt_type = option_hdr->ip6o_type;
            uint8_t ip6opt_len = option_hdr->ip6o_len;

            if (ip6opt_len > 0) {
                uint8_t ip6ioam_type = *(uint8_t *)(option_hdr + sizeof(struct ip6_opt));

                // For testing
                #define IOAM_PREALLOC_TRACE 0
                if (ip6ioam_type == IOAM_PREALLOC_TRACE) {
                    // For debugging
                    print_ip6_address(&ipv6_header->ip6_src);

                    // Send a response packet back to the source
                    cringe_loopback(packet);
                }
            }
        }
    }
}

void list_devices() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    printf("Available devices:\n");
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%s", d->name);
        if (d->description) {
            printf(" (%s)", d->description);
        }
        printf("\n");
    }

    pcap_freealldevs(alldevs);
}

void usage(char *prog_name) {
    fprintf(stderr, "Usage: %s [-i <interface>] [-l]\n", prog_name);
    fprintf(stderr, "    -i <interface>  Specify the interface to capture packets on\n");
    fprintf(stderr, "    -l              List all available interfaces\n");
}

int main(int argc, char *argv[]) {
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "ip6"; // Filter for IPv6 packets
    bpf_u_int32 net;
    int opt;

    // Parse command-line options
    while ((opt = getopt(argc, argv, "i:l")) != -1) {
        switch (opt) {
            case 'i':
                dev = optarg;
                break;
            case 'l':
                list_devices();
                exit(EXIT_SUCCESS);
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (dev == NULL) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Open the capture device
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // Capture packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the session
    pcap_close(handle);

    return 0;
}
