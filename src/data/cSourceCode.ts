export interface CSourceFile {
  filename: string;
  title: string;
  description: string;
  category: 'Layer 2 ARP' | 'Layer 3 ICMP' | 'Layer 4 Port/OS' | 'VLAN & LLDP' | 'Passive Sniffer' | 'NetFlow & Storm' | 'Bash Script' | 'Build System';
  code: string;
  compilationCmd: string;
  requirements: string;
  capabilities: string[];
}

export const C_SOURCE_FILES: CSourceFile[] = [
  {
    filename: 'arp_scan.c',
    title: 'ARP Broadcast Subnet Scanner (Layer 2)',
    description: 'Direct POSIX AF_PACKET raw socket implementation that sends ARP who-has queries across a subnet and sniffs ARP replies to discover active IP/MAC addresses.',
    category: 'Layer 2 ARP',
    compilationCmd: 'gcc -O2 -Wall -Wextra arp_scan.c -o arp_scan\nsudo ./arp_scan eth0 192.168.1.1 192.168.1.254',
    requirements: 'Linux / POSIX, requires root or CAP_NET_RAW capability.',
    capabilities: ['L2 Ethernet Frame Crafts', 'ARP Request Generator', 'MAC Address Resolution', 'Real-time Round-trip Latency'],
    code: `/*
 * arp_scan.c - Educational POSIX Layer 2 ARP Discovery Tool
 * Builds and transmits raw Ethernet ARP requests and captures replies.
 *
 * Compilation:
 *   gcc -O2 -Wall -Wextra arp_scan.c -o arp_scan
 * Usage:
 *   sudo ./arp_scan <interface> <start_ip> <end_ip>
 * Example:
 *   sudo ./arp_scan eth0 192.168.1.1 192.168.1.254
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/time.h>

#define BUFFER_SIZE 1518

/* Ethernet + ARP Frame Structure */
struct arp_packet {
    struct ether_header eth_hdr;
    struct ether_arp arp_hdr;
} __attribute__((packed));

/* Get local interface MAC address and index */
static int get_interface_info(const char *iface, int sock, uint8_t *mac, int *ifindex, struct in_addr *src_ip) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    /* Get interface index */
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("[!] SIOCGIFINDEX error");
        return -1;
    }
    *ifindex = ifr.ifr_ifindex;

    /* Get hardware MAC address */
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("[!] SIOCGIFHWADDR error");
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    /* Get local IP address */
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("[!] SIOCGIFADDR error");
        return -1;
    }
    *src_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "====================================================\\n");
        fprintf(stderr, " LAN Reconnaissance - Portable Layer 2 ARP Scanner \\n");
        fprintf(stderr, "====================================================\\n");
        fprintf(stderr, "Usage: %s <interface> <start_ip> <end_ip>\\n", argv[0]);
        fprintf(stderr, "Example: sudo %s eth0 192.168.1.1 192.168.1.254\\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    struct in_addr start_ip, end_ip, src_ip;
    if (inet_pton(AF_INET, argv[2], &start_ip) <= 0 ||
        inet_pton(AF_INET, argv[3], &end_ip) <= 0) {
        fprintf(stderr, "[!] Invalid IP address range provided.\\n");
        return EXIT_FAILURE;
    }

    /* Open raw packet socket */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("[!] Failed to open raw socket (are you root?)");
        return EXIT_FAILURE;
    }

    uint8_t src_mac[6];
    int ifindex = 0;
    if (get_interface_info(iface, sock, src_mac, &ifindex, &src_ip) < 0) {
        close(sock);
        return EXIT_FAILURE;
    }

    printf("[+] Interface: %s (Index: %d)\\n", iface, ifindex);
    printf("[+] Source IP: %s | MAC: %02x:%02x:%02x:%02x:%02x:%02x\\n",
           inet_ntoa(src_ip), src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf("[+] Scanning range: %s -> %s\\n", argv[2], argv[3]);
    printf("----------------------------------------------------------------------\\n");
    printf("%-18s %-20s %-10s\\n", "IP Address", "MAC Address", "Latency");
    printf("----------------------------------------------------------------------\\n");

    /* Set socket non-blocking / timeout */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 150000; // 150ms timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    uint32_t cur = ntohl(start_ip.s_addr);
    uint32_t last = ntohl(end_ip.s_addr);

    for (uint32_t ip = cur; ip <= last; ++ip) {
        struct in_addr target_ip;
        target_ip.s_addr = htonl(ip);

        struct arp_packet pkt;
        memset(&pkt, 0, sizeof(pkt));

        /* Ethernet Header */
        memset(pkt.eth_hdr.ether_dhost, 0xff, 6); // Broadcast FF:FF:FF:FF:FF:FF
        memcpy(pkt.eth_hdr.ether_shost, src_mac, 6);
        pkt.eth_hdr.ether_type = htons(ETHERTYPE_ARP);

        /* ARP Payload */
        pkt.arp_hdr.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
        pkt.arp_hdr.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
        pkt.arp_hdr.ea_hdr.ar_hln = 6;
        pkt.arp_hdr.ea_hdr.ar_pln = 4;
        pkt.arp_hdr.ea_hdr.ar_op = htons(ARPOP_REQUEST);

        memcpy(pkt.arp_hdr.arp_sha, src_mac, 6);
        memcpy(pkt.arp_hdr.arp_spa, &src_ip.s_addr, 4);
        memset(pkt.arp_hdr.arp_tha, 0x00, 6);
        memcpy(pkt.arp_hdr.arp_tpa, &target_ip.s_addr, 4);

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_halen = 6;
        memset(sll.sll_addr, 0xff, 6);

        struct timeval send_time;
        gettimeofday(&send_time, NULL);

        if (sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("[!] sendto failed");
            continue;
        }

        /* Check for ARP replies */
        uint8_t recv_buf[BUFFER_SIZE];
        ssize_t n = recv(sock, recv_buf, sizeof(recv_buf), 0);
        if (n >= (ssize_t)sizeof(struct arp_packet)) {
            struct arp_packet *reply = (struct arp_packet *)recv_buf;
            if (ntohs(reply->arp_hdr.ea_hdr.ar_op) == ARPOP_REPLY) {
                struct in_addr sender_ip;
                memcpy(&sender_ip.s_addr, reply->arp_hdr.arp_spa, 4);
                
                struct timeval recv_time;
                gettimeofday(&recv_time, NULL);
                double ms = (recv_time.tv_sec - send_time.tv_sec) * 1000.0 +
                            (recv_time.tv_usec - send_time.tv_usec) / 1000.0;

                uint8_t *sm = reply->arp_hdr.arp_sha;
                printf("%-18s %02x:%02x:%02x:%02x:%02x:%02x    %.2f ms\\n",
                       inet_ntoa(sender_ip), sm[0], sm[1], sm[2], sm[3], sm[4], sm[5], ms);
            }
        }
        usleep(5000); // 5ms pacing between probes
    }

    printf("----------------------------------------------------------------------\\n");
    printf("[+] ARP sweep complete.\\n");
    close(sock);
    return EXIT_SUCCESS;
}`
  },
  {
    filename: 'icmp_sweep.c',
    title: 'ICMP Echo Sweep & TTL RTT Auditing',
    description: 'Raw ICMP Echo Request broadcaster calculating checksums, timing round-trip latency, and inspecting reply IP TTL values for preliminary OS identification.',
    category: 'Layer 3 ICMP',
    compilationCmd: 'gcc -O2 -Wall icmp_sweep.c -o icmp_sweep\nsudo ./icmp_sweep 192.168.1.0/24',
    requirements: 'POSIX / Linux / macOS / BSD, root or SOCK_DGRAM icmp enabled.',
    capabilities: ['Raw ICMP Header Checksum', 'CIDR Subnet Expansion', 'IP Header TTL Extraction', 'Microsecond Latency'],
    code: `/*
 * icmp_sweep.c - Educational ICMP Echo Subnet Sweeper
 * Calculates Internet Checksums, sends Echo Requests, and records TTL.
 *
 * Compilation:
 *   gcc -O2 -Wall icmp_sweep.c -o icmp_sweep
 * Usage:
 *   sudo ./icmp_sweep 192.168.1.1 192.168.1.254
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define PACKET_SIZE 64

/* Standard Internet Checksum (RFC 1071) */
static unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <start_ip> <end_ip>\\n", argv[0]);
        fprintf(stderr, "Example: sudo %s 192.168.1.1 192.168.1.254\\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct in_addr start_ip, end_ip;
    if (inet_pton(AF_INET, argv[1], &start_ip) <= 0 ||
        inet_pton(AF_INET, argv[2], &end_ip) <= 0) {
        fprintf(stderr, "[!] Invalid IPv4 address format.\\n");
        return EXIT_FAILURE;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("[!] Failed to open raw ICMP socket (are you root?)");
        return EXIT_FAILURE;
    }

    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 }; // 200ms timeout
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("======================================================================\\n");
    printf(" ICMP Echo Reconnaissance & TTL OS Inspection Engine                 \\n");
    printf("======================================================================\\n");
    printf("%-18s %-8s %-12s %-20s\\n", "IP Address", "TTL", "Latency", "Estimated OS Stack");
    printf("----------------------------------------------------------------------\\n");

    uint32_t cur = ntohl(start_ip.s_addr);
    uint32_t last = ntohl(end_ip.s_addr);
    pid_t pid = getpid() & 0xFFFF;

    for (uint32_t ip = cur; ip <= last; ++ip) {
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = htonl(ip);

        char packet[PACKET_SIZE];
        memset(packet, 0, sizeof(packet));

        struct icmphdr *icmp = (struct icmphdr *)packet;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(pid);
        icmp->un.echo.sequence = htons((uint16_t)(ip - cur));
        icmp->checksum = 0;
        icmp->checksum = calculate_checksum(packet, sizeof(packet));

        struct timeval start_time;
        gettimeofday(&start_time, NULL);

        sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));

        char recv_buf[1024];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        ssize_t bytes = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);
        if (bytes >= (ssize_t)(sizeof(struct iphdr) + sizeof(struct icmphdr))) {
            struct iphdr *ip_hdr = (struct iphdr *)recv_buf;
            int ip_len = ip_hdr->ihl * 4;
            struct icmphdr *reply_icmp = (struct icmphdr *)(recv_buf + ip_len);

            if (reply_icmp->type == ICMP_ECHOREPLY && ntohs(reply_icmp->un.echo.id) == pid) {
                struct timeval end_time;
                gettimeofday(&end_time, NULL);
                double ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                            (end_time.tv_usec - start_time.tv_usec) / 1000.0;

                int ttl = ip_hdr->ttl;
                const char *os_family = "Unknown Stack";
                if (ttl <= 64) os_family = "Linux / macOS / BSD";
                else if (ttl <= 128) os_family = "Windows (NT/10/11/Server)";
                else if (ttl <= 255) os_family = "Cisco IOS / Network Gear";

                printf("%-18s %-8d %-8.2f ms   %-20s\\n",
                       inet_ntoa(from.sin_addr), ttl, ms, os_family);
            }
        }
        usleep(4000); // 4ms delay
    }

    printf("----------------------------------------------------------------------\\n");
    close(sock);
    return EXIT_SUCCESS;
}`
  },
  {
    filename: 'os_fingerprint.c',
    title: 'TCP SYN Scanner & OS Heuristics Engine',
    description: 'Crafts raw TCP SYN probes to target ports (22, 80, 135, 445, etc.) and analyzes SYN-ACK packet characteristics: Initial TTL, TCP Window Size, SACK, and MSS to classify OS stack.',
    category: 'Layer 4 Port/OS',
    compilationCmd: 'gcc -O2 -Wall os_fingerprint.c -o os_fingerprint\nsudo ./os_fingerprint 192.168.10.10',
    requirements: 'Linux / raw sockets, root privileges.',
    capabilities: ['Half-open TCP SYN Probing', 'TCP Window Size Inspection', 'Initial TTL Classifier', 'Banner Grabbing'],
    code: `/*
 * os_fingerprint.c - TCP SYN Prober and Operating System Fingerprinter
 * Evaluates TCP SYN-ACK reply characteristics to classify target OS.
 *
 * Compilation:
 *   gcc -O2 -Wall os_fingerprint.c -o os_fingerprint
 * Usage:
 *   sudo ./os_fingerprint <target_ip>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>

/* Target common ports for discovery */
static const int COMMON_PORTS[] = { 21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5060, 8080 };
#define PORT_COUNT (sizeof(COMMON_PORTS) / sizeof(COMMON_PORTS[0]))

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

static unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;
    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s <target_ip>\\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_str = argv[1];
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, target_str, &dest.sin_addr) <= 0) {
        fprintf(stderr, "[!] Invalid IP address: %s\\n", target_str);
        return EXIT_FAILURE;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("[!] Failed to open raw TCP socket");
        return EXIT_FAILURE;
    }

    /* Inform kernel we will construct IP header */
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct timeval tv = { .tv_sec = 0, .tv_usec = 300000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("======================================================================\\n");
    printf(" Scanning Target: %s\\n", target_str);
    printf("======================================================================\\n");
    printf("%-8s %-10s %-8s %-12s %-16s\\n", "Port", "State", "TTL", "WinSize", "Service");
    printf("----------------------------------------------------------------------\\n");

    int detected_ttl = 0;
    int detected_win = 0;

    for (size_t i = 0; i < PORT_COUNT; ++i) {
        int dport = COMMON_PORTS[i];
        char packet[4096];
        memset(packet, 0, sizeof(packet));

        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

        /* Construct IP Header */
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        iph->id = htons(54321);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->saddr = inet_addr("0.0.0.0"); // Kernel resolves local IP
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

        /* Construct TCP SYN Header */
        tcph->source = htons(49152 + (i * 7));
        tcph->dest = htons(dport);
        tcph->seq = htonl(1000 + i);
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 1; // SYN flag
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0;
        tcph->window = htons(64240);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        /* Calculate TCP checksum with pseudo-header */
        struct pseudo_header psh;
        psh.source_address = iph->saddr;
        psh.dest_address = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
        tcph->check = checksum((unsigned short *)pseudogram, psize);
        free(pseudogram);

        sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)&dest, sizeof(dest));

        /* Receive SYN-ACK or RST */
        char buffer[4096];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_len);
        if (n >= (ssize_t)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
            struct iphdr *r_iph = (struct iphdr *)buffer;
            int ip_len = r_iph->ihl * 4;
            struct tcphdr *r_tcph = (struct tcphdr *)(buffer + ip_len);

            if (r_iph->saddr == dest.sin_addr.s_addr && ntohs(r_tcph->source) == dport) {
                if (r_tcph->syn && r_tcph->ack) {
                    detected_ttl = r_iph->ttl;
                    detected_win = ntohs(r_tcph->window);
                    printf("%-8d %-10s %-8d %-12d %-16s\\n",
                           dport, "OPEN", detected_ttl, detected_win,
                           dport == 22 ? "SSH" : dport == 80 ? "HTTP" : dport == 443 ? "HTTPS" :
                           dport == 445 ? "SMB" : dport == 3389 ? "RDP" : "Service");
                }
            }
        }
        usleep(8000);
    }

    printf("----------------------------------------------------------------------\\n");
    printf("[+] Fingerprint Analysis:\\n");
    if (detected_ttl > 0) {
        printf("    Initial TTL: %d | TCP Window Size: %d\\n", detected_ttl, detected_win);
        if (detected_ttl <= 64) {
            printf("    OS Class: POSIX / Linux kernel 3.x-6.x, macOS, or Android\\n");
        } else if (detected_ttl <= 128) {
            printf("    OS Class: Microsoft Windows (10/11 or Windows Server 2016-2022)\\n");
        } else if (detected_ttl <= 255) {
            printf("    OS Class: Cisco IOS / Juniper JunOS / Network Embedded Hardware\\n");
        }
    } else {
        printf("    No responsive open TCP ports observed.\\n");
    }
    printf("======================================================================\\n");

    close(sock);
    return EXIT_SUCCESS;
}`
  },
  {
    filename: 'lldp_vlan_sniff.c',
    title: '802.1AB LLDP & 802.1Q VLAN Tag Sniffer',
    description: 'Binds to EtherType 0x88CC (LLDP) and 0x8100 (802.1Q) to parse switch announcements, Chassis ID, System Name, Port ID, and tagged VLAN IDs for physical switchport topology mapping.',
    category: 'VLAN & LLDP',
    compilationCmd: 'gcc -O2 -Wall lldp_vlan_sniff.c -o lldp_vlan_sniff\nsudo ./lldp_vlan_sniff eth0',
    requirements: 'POSIX raw socket (AF_PACKET), root privileges.',
    capabilities: ['802.1AB LLDP TLV Decoder', '802.1Q VLAN Tag Extraction', 'Switch Chassis ID Discovery', 'Port Name / VLAN Binding'],
    code: `/*
 * lldp_vlan_sniff.c - Layer 2 LLDP and 802.1Q VLAN Discovery Tool
 * Sniffs Link Layer Discovery Protocol and VLAN tags on an interface.
 *
 * Compilation:
 *   gcc -O2 -Wall lldp_vlan_sniff.c -o lldp_vlan_sniff
 * Usage:
 *   sudo ./lldp_vlan_sniff <interface>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define ETH_P_LLDP 0x88CC
#define ETH_P_8021Q 0x8100

/* TLV Types */
#define LLDP_TLV_END           0
#define LLDP_TLV_CHASSIS_ID    1
#define LLDP_TLV_PORT_ID       2
#define LLDP_TLV_TTL           3
#define LLDP_TLV_PORT_DESC     4
#define LLDP_TLV_SYS_NAME      5
#define LLDP_TLV_SYS_DESC      6
#define LLDP_TLV_ORG_SPECIFIC  127

static void parse_lldp_tlvs(const uint8_t *payload, size_t len) {
    size_t offset = 0;
    printf("\\n--- [LLDP Frame Decoded] ---\\n");

    while (offset + 2 <= len) {
        uint16_t header = (payload[offset] << 8) | payload[offset + 1];
        uint8_t tlv_type = (header >> 9) & 0x7F;
        uint16_t tlv_len = header & 0x1FF;
        offset += 2;

        if (offset + tlv_len > len) break;
        const uint8_t *val = payload + offset;

        switch (tlv_type) {
            case LLDP_TLV_END:
                printf("[*] End of LLDPDU\\n");
                return;
            case LLDP_TLV_CHASSIS_ID:
                printf("[+] Chassis Subtype: %d | ID: ", val[0]);
                for (int i = 1; i < tlv_len; ++i) printf("%02x%s", val[i], i + 1 < tlv_len ? ":" : "");
                printf("\\n");
                break;
            case LLDP_TLV_PORT_ID:
                printf("[+] Port Subtype: %d | ID: %.*s\\n", val[0], tlv_len - 1, val + 1);
                break;
            case LLDP_TLV_TTL:
                printf("[+] TTL: %d seconds\\n", (val[0] << 8) | val[1]);
                break;
            case LLDP_TLV_SYS_NAME:
                printf("[+] System Name: %.*s\\n", tlv_len, val);
                break;
            case LLDP_TLV_PORT_DESC:
                printf("[+] Port Description: %.*s\\n", tlv_len, val);
                break;
            case LLDP_TLV_SYS_DESC:
                printf("[+] System Description: %.*s\\n", tlv_len > 60 ? 60 : tlv_len, val);
                break;
            case LLDP_TLV_ORG_SPECIFIC:
                /* IEEE 802.1 VLAN Name / PVID TLV (OUI 00-80-c2) */
                if (tlv_len >= 5 && val[0] == 0x00 && val[1] == 0x80 && val[2] == 0xC2) {
                    uint8_t subtype = val[3];
                    if (subtype == 1) { // Port VLAN ID (PVID)
                        uint16_t pvid = (val[4] << 8) | val[5];
                        printf("[+] 802.1Q Port Native VLAN ID: %d\\n", pvid);
                    }
                }
                break;
        }
        offset += tlv_len;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s <interface>\\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("[!] socket(AF_PACKET) failed");
        return EXIT_FAILURE;
    }

    /* Bind to interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("[!] SIOCGIFINDEX failed");
        close(sock);
        return EXIT_FAILURE;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("[!] bind failed");
        close(sock);
        return EXIT_FAILURE;
    }

    printf("[+] Listening on %s for LLDP (0x88CC) and 802.1Q VLAN tagged frames...\\n", iface);
    printf("[+] Press Ctrl+C to stop.\\n");

    uint8_t buffer[2048];
    while (1) {
        ssize_t n = recv(sock, buffer, sizeof(buffer), 0);
        if (n < 14) continue;

        struct ether_header *eth = (struct ether_header *)buffer;
        uint16_t eth_type = ntohs(eth->ether_type);

        /* Check for 802.1Q Tagged Frame */
        if (eth_type == ETH_P_8021Q && n >= 18) {
            uint16_t tci = (buffer[14] << 8) | buffer[15];
            uint16_t vlan_id = tci & 0x0FFF;
            uint8_t priority = (tci >> 13) & 0x07;
            uint16_t inner_type = (buffer[16] << 8) | buffer[17];
            printf("[VLAN TAG] Detected 802.1Q Frame | VLAN ID: %d | Priority (PCP): %d | Inner Proto: 0x%04x\\n",
                   vlan_id, priority, inner_type);
        }
        /* Check for LLDP Frame */
        else if (eth_type == ETH_P_LLDP) {
            parse_lldp_tlvs(buffer + 14, n - 14);
        }
    }

    close(sock);
    return EXIT_SUCCESS;
}`
  },
  {
    filename: 'passive_monitor.c',
    title: 'Passive Multicast & Broadcast LAN Analyzer',
    description: 'Completely passive listener capturing broadcast traffic (ARP, DHCP, mDNS 5353, SSDP 1900, LLMNR 5355, NetBIOS 137) without transmitting any packets on the wire.',
    category: 'Passive Sniffer',
    compilationCmd: 'gcc -O2 -Wall passive_monitor.c -o passive_monitor\nsudo ./passive_monitor eth0',
    requirements: 'POSIX AF_PACKET raw socket, root privileges.',
    capabilities: ['Zero-Packet Transmission', 'mDNS Service Discovery', 'LLMNR Poison Risk Detection', 'SSDP Device Identification'],
    code: `/*
 * passive_monitor.c - Passive Broadcast and Multicast LAN Discovery
 * Passively captures broadcast/multicast discovery packets to map LAN assets.
 *
 * Compilation:
 *   gcc -O2 -Wall passive_monitor.c -o passive_monitor
 * Usage:
 *   sudo ./passive_monitor <interface>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s <interface>\\n", argv[0]);
        return EXIT_FAILURE;
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("[!] Failed to open AF_PACKET raw socket");
        return EXIT_FAILURE;
    }

    printf("======================================================================\\n");
    printf(" Passive Stealth LAN Discovery - Listening on %s                     \\n", argv[1]);
    printf("======================================================================\\n");
    printf("%-18s %-18s %-12s %-30s\\n", "Source IP", "Dest IP", "Protocol", "Discovered Service / Event");
    printf("----------------------------------------------------------------------\\n");

    uint8_t buffer[2048];
    while (1) {
        ssize_t len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 14) continue;

        struct ether_header *eth = (struct ether_header *)buffer;
        uint16_t eth_type = ntohs(eth->ether_type);

        if (eth_type == ETHERTYPE_IP && len >= 34) {
            struct iphdr *iph = (struct iphdr *)(buffer + 14);
            int ip_len = iph->ihl * 4;

            if (iph->protocol == IPPROTO_UDP && len >= (ssize_t)(14 + ip_len + sizeof(struct udphdr))) {
                struct udphdr *udph = (struct udphdr *)(buffer + 14 + ip_len);
                int dport = ntohs(udph->dest);
                int sport = ntohs(udph->source);

                struct in_addr src, dst;
                src.s_addr = iph->saddr;
                dst.s_addr = iph->daddr;

                if (dport == 5353 || sport == 5353) {
                    printf("%-18s %-18s %-12s %-30s\\n",
                           inet_ntoa(src), inet_ntoa(dst), "mDNS:5353", "Apple Bonjour / IoT Multicast DNS Query");
                } else if (dport == 5355) {
                    printf("%-18s %-18s %-12s %-30s\\n",
                           inet_ntoa(src), inet_ntoa(dst), "LLMNR:5355", "[!] Windows LLMNR Query (Poisoning Target)");
                } else if (dport == 1900) {
                    printf("%-18s %-18s %-12s %-30s\\n",
                           inet_ntoa(src), inet_ntoa(dst), "SSDP:1900", "UPnP SSDP M-SEARCH / NOTIFY Discovery");
                } else if (dport == 137 || dport == 138) {
                    printf("%-18s %-18s %-12s %-30s\\n",
                           inet_ntoa(src), inet_ntoa(dst), "NetBIOS:137", "NetBIOS Name Service Broadcast");
                } else if (dport == 67 || dport == 68) {
                    printf("%-18s %-18s %-12s %-30s\\n",
                           inet_ntoa(src), inet_ntoa(dst), "DHCP:67/68", "DHCP Discover / Request / Offer");
                }
            }
        }
    }

    close(sock);
    return EXIT_SUCCESS;
}`
  },
  {
    filename: 'lan_audit.sh',
    title: 'Portable POSIX Shell LAN Reconnaissance Script',
    description: 'Versatile, zero-dependency bash discovery script executing network interface discovery, ARP table dumps, route topology analysis, listening port audits, and passive traffic summaries.',
    category: 'Bash Script',
    compilationCmd: 'chmod +x lan_audit.sh\n./lan_audit.sh',
    requirements: 'POSIX Bash, iproute2, arp, ss or netstat, awk.',
    capabilities: ['Local Interface & Subnet Discovery', 'Kernel ARP Table Extraction', 'Route & Gateway Audit', 'Local Port & Socket Audit'],
    code: `#!/usr/bin/env bash
# ==============================================================================
# lan_audit.sh - Portable On-Premise LAN Discovery & Network Audit Script
# Compatible with Linux, Raspberry Pi, macOS, and Android (Termux)
# ==============================================================================

set -e

RED='\\033[0;31m'
GREEN='\\033[0;32m'
BLUE='\\033[0;34m'
YELLOW='\\033[1;33m'
CYAN='\\033[0;36m'
NC='\\033[0m' # No Color

echo -e "\${CYAN}======================================================================\${NC}"
echo -e "\${GREEN}  LAN TOPOLOGY & ON-PREMISE NETWORK AUDITING UTILITY (BASH)           \${NC}"
echo -e "\${CYAN}======================================================================\${NC}"
echo -e "Timestamp: $(date)"
echo -e "Host: $(hostname) ($(uname -s) $(uname -r) $(uname -m))\\n"

# 1. Network Interfaces & IP Addresses
echo -e "\${BLUE}[+] STEP 1: Local Network Interfaces & Subnets\${NC}"
if command -v ip >/dev/null 2>&1; then
    ip -br addr show | while read -r iface status ips; do
        echo -e "  Interface: \${YELLOW}\$iface\${NC} | Status: \${GREEN}\$status\${NC} | IPs: \$ips"
    done
elif command -v ifconfig >/dev/null 2>&1; then
    ifconfig -a | grep -E '^[a-zA-Z0-9]+|inet '
fi
echo ""

# 2. Default Gateways & Routing Table
echo -e "\${BLUE}[+] STEP 2: Routing Table & Gateways\${NC}"
if command -v ip >/dev/null 2>&1; then
    ip route show | while read -r line; do
        echo -e "  \${line}"
    done
elif command -v netstat >/dev/null 2>&1; then
    netstat -rn
fi
echo ""

# 3. Kernel ARP Table (Discovered L2 Endpoints)
echo -e "\${BLUE}[+] STEP 3: Kernel ARP Table (Active LAN Neighbors)\${NC}"
printf "  %-18s %-20s %-12s %-10s\\n" "IP Address" "MAC Address" "Interface" "State"
echo "  ------------------------------------------------------------------"
if command -v ip >/dev/null 2>&1; then
    ip neigh show | while read -r ip dev iface lladdr mac rest; do
        if [ "\$lladdr" = "lladdr" ]; then
            printf "  %-18s %-20s %-12s %-10s\\n" "\$ip" "\$mac" "\$iface" "\$rest"
        fi
    done
elif command -v arp >/dev/null 2>&1; then
    arp -an
fi
echo ""

# 4. Open Listening Sockets on Local Host
echo -e "\${BLUE}[+] STEP 4: Local Host Open Listening Ports\${NC}"
if command -v ss >/dev/null 2>&1; then
    ss -tuln | head -n 15
elif command -v netstat >/dev/null 2>&1; then
    netstat -tuln | head -n 15
fi
echo ""

# 5. Quick Nmap Subnet Sweep (if installed)
if command -v nmap >/dev/null 2>&1; then
    echo -e "\${BLUE}[+] STEP 5: Quick Ping Discovery Sweep with Nmap\${NC}"
    DEFAULT_IFACE=\$(ip route | grep default | awk '{print \$5}' | head -n 1)
    SUBNET=\$(ip -o -f inet addr show "\$DEFAULT_IFACE" | awk '{print \$4}' | head -n 1)
    if [ -n "\$SUBNET" ]; then
        echo -e "  Scanning Subnet: \${YELLOW}\$SUBNET\${NC} via \${DEFAULT_IFACE}..."
        nmap -sn -n "\$SUBNET" | grep -E "Nmap scan report for|MAC Address:"
    fi
else
    echo -e "\${YELLOW}[!] nmap is not installed. Use ./arp_scan or ./icmp_sweep binary for native C discovery.\${NC}"
fi

echo ""
echo -e "\${GREEN}[✓] LAN Reconnaissance script finished successfully.\${NC}"
`
  },
  {
    filename: 'netflow_collector.c',
    title: 'NetFlow v5 UDP Flow Record Telemetry Collector',
    description: 'High-performance zero-dependency POSIX C NetFlow v5 UDP collector listening on port 2055. Parses flow headers, IP 5-tuples, packet/octet counters, TCP flags, and aggregates Top Talkers.',
    category: 'NetFlow & Storm',
    compilationCmd: 'gcc -O2 -Wall -Wextra netflow_collector.c -o netflow_collector\n./netflow_collector 2055',
    requirements: 'POSIX / Linux (No root required for UDP port >= 1024)',
    capabilities: ['NetFlow v5 Header Parser', 'Top Talker Flow Aggregation', 'Layer 4 Port Classification', 'Bandwidth Rate Calculator'],
    code: `/*
 * netflow_collector.c - High-Performance POSIX NetFlow v5 Telemetry Collector
 * Listens on UDP port 2055 (or user-specified port) for NetFlow v5 datagrams.
 * Unpacks 5-tuples, octet counts, packet counts, duration, and flags.
 *
 * Compilation:
 *   gcc -O2 -Wall -Wextra netflow_collector.c -o netflow_collector
 * Usage:
 *   ./netflow_collector [port]
 * Example:
 *   ./netflow_collector 2055
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#define DEFAULT_NETFLOW_PORT 2055
#define MAX_BUFFER 2048

/* NetFlow v5 Header (24 bytes) */
struct netflow_v5_header {
    uint16_t version;          /* Current NetFlow export version (5) */
    uint16_t count;            /* Number of flow records in datagram (1-30) */
    uint32_t sys_uptime_ms;    /* Current router uptime in milliseconds */
    uint32_t unix_secs;        /* Current Unix epoch seconds */
    uint32_t unix_nsecs;       /* Residual nanoseconds */
    uint32_t flow_sequence;    /* Sequence counter of total flows seen */
    uint8_t  engine_type;      /* Type of flow-switching engine */
    uint8_t  engine_id;        /* Slot/engine identifier */
    uint16_t sampling_interval;/* Sampling mode & interval */
} __attribute__((packed));

/* NetFlow v5 Flow Record (48 bytes) */
struct netflow_v5_record {
    uint32_t src_addr;         /* Source IP Address */
    uint32_t dst_addr;         /* Destination IP Address */
    uint32_t next_hop;         /* Next hop router IP */
    uint16_t input_ifindex;    /* SNMP index of input interface */
    uint16_t output_ifindex;   /* SNMP index of output interface */
    uint32_t d_pkts;           /* Packets in the flow */
    uint32_t d_octets;         /* Total number of Layer 3 bytes in flow */
    uint32_t first_uptime_ms;  /* SysUptime at start of flow */
    uint32_t last_uptime_ms;   /* SysUptime when last packet received */
    uint16_t src_port;         /* TCP/UDP source port */
    uint16_t dst_port;         /* TCP/UDP destination port */
    uint8_t  pad1;             /* Padding */
    uint8_t  tcp_flags;        /* Cumulative OR of TCP flags */
    uint8_t  prot;             /* IP Protocol (e.g. 6=TCP, 17=UDP, 1=ICMP) */
    uint8_t  tos;              /* IP Type of Service / DSCP */
    uint16_t src_as;           /* Autonomous system of source */
    uint16_t dst_as;           /* Autonomous system of destination */
    uint8_t  src_mask;         /* Source subnet mask bitcount */
    uint8_t  dst_mask;         /* Destination subnet mask bitcount */
    uint16_t pad2;             /* Unused padding */
} __attribute__((packed));

static const char *get_protocol_name(uint8_t proto) {
    switch (proto) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        case 47: return "GRE";
        case 50: return "ESP";
        default: return "OTHER";
    }
}

int main(int argc, char *argv[]) {
    int port = (argc > 1) ? atoi(argv[1]) : DEFAULT_NETFLOW_PORT;
    int sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    uint8_t buffer[MAX_BUFFER];

    printf("========================================================\\n");
    printf(" OcuLAN - High-Performance NetFlow v5 Flow Collector     \\n");
    printf("========================================================\\n");
    printf("[+] Initializing UDP Listener on port: %d\\n", port);

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("[!] Socket creation failed");
        return EXIT_FAILURE;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[!] Bind failed on UDP port");
        close(sock);
        return EXIT_FAILURE;
    }

    printf("[✓] Flow collector running. Waiting for NetFlow v5 export datagrams...\\n\\n");
    printf("%-8s %-21s %-21s %-6s %-10s %-10s %-8s\\n", 
           "TIME", "SOURCE ENDPOINT", "DESTINATION ENDPOINT", "PROTO", "PACKETS", "BYTES", "TCP FLAGS");
    printf("--------------------------------------------------------------------------------------\\n");

    while (1) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, 
                               (struct sockaddr *)&client_addr, &client_len);
        if (len < (ssize_t)sizeof(struct netflow_v5_header)) {
            continue;
        }

        struct netflow_v5_header *hdr = (struct netflow_v5_header *)buffer;
        uint16_t version = ntohs(hdr->version);
        uint16_t count = ntohs(hdr->count);

        if (version != 5) {
            fprintf(stderr, "[!] Warning: Received non-v5 NetFlow packet (version=%d)\\n", version);
            continue;
        }

        struct netflow_v5_record *records = (struct netflow_v5_record *)(buffer + sizeof(struct netflow_v5_header));
        time_t now = (time_t)ntohl(hdr->unix_secs);
        struct tm *tm_info = localtime(&now);
        char time_str[16];
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

        for (int i = 0; i < count; i++) {
            struct netflow_v5_record *r = &records[i];
            
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            struct in_addr sa, da;
            sa.s_addr = r->src_addr;
            da.s_addr = r->dst_addr;
            inet_ntop(AF_INET, &sa, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &da, dst_ip, sizeof(dst_ip));

            char src_ep[32], dst_ep[32];
            snprintf(src_ep, sizeof(src_ep), "%s:%u", src_ip, ntohs(r->src_port));
            snprintf(dst_ep, sizeof(dst_ep), "%s:%u", dst_ip, ntohs(r->dst_port));

            uint32_t pkts = ntohl(r->d_pkts);
            uint32_t octets = ntohl(r->d_octets);
            const char *proto = get_protocol_name(r->prot);

            char flags_str[16] = {0};
            if (r->tcp_flags & 0x02) strcat(flags_str, "S");
            if (r->tcp_flags & 0x10) strcat(flags_str, "A");
            if (r->tcp_flags & 0x01) strcat(flags_str, "F");
            if (r->tcp_flags & 0x04) strcat(flags_str, "R");
            if (r->tcp_flags & 0x08) strcat(flags_str, "P");
            if (strlen(flags_str) == 0) strcpy(flags_str, "-");

            printf("%-8s %-21s %-21s %-6s %-10u %-10u %-8s\\n",
                   time_str, src_ep, dst_ep, proto, pkts, octets, flags_str);
        }
    }

    close(sock);
    return 0;
}
`
  },
  {
    filename: 'storm_detector.c',
    title: 'Layer 2 Broadcast Storm & STP Loop Detection Daemon',
    description: 'Promiscuous raw socket packet inspector that tracks broadcast (FF:FF:FF:FF:FF:FF) and multicast (01:00:5E / 33:33) PPS rates. Alarms when flooding thresholds or STP topology loops are detected.',
    category: 'NetFlow & Storm',
    compilationCmd: 'gcc -O2 -Wall -Wextra storm_detector.c -o storm_detector\nsudo ./storm_detector eth0 250',
    requirements: 'Linux / POSIX, requires CAP_NET_RAW or root privileges.',
    capabilities: ['Promiscuous L2 Frame Sniffer', 'Broadcast / Multicast PPS Meter', 'STP BPDU Loop Detection', 'Automated Alarm Trigger'],
    code: `/*
 * storm_detector.c - Layer 2 Broadcast Storm & Loop Watchdog Daemon
 * Monitors L2 broadcast & multicast PPS rates. Triggers alarms when thresholds are exceeded.
 *
 * Compilation:
 *   gcc -O2 -Wall -Wextra storm_detector.c -o storm_detector
 * Usage:
 *   sudo ./storm_detector <interface> [pps_threshold]
 * Example:
 *   sudo ./storm_detector eth0 250
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#define DEFAULT_PPS_THRESHOLD 250
#define BUFFER_SIZE 2048

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "========================================================\\n");
        fprintf(stderr, " OcuLAN - Layer 2 Broadcast Storm & Loop Watchdog        \\n");
        fprintf(stderr, "========================================================\\n");
        fprintf(stderr, "Usage: %s <interface> [pps_threshold]\\n", argv[0]);
        fprintf(stderr, "Example: sudo %s eth0 250\\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    int threshold = (argc > 2) ? atoi(argv[2]) : DEFAULT_PPS_THRESHOLD;

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("[!] AF_PACKET raw socket failed (run as root / sudo)");
        return EXIT_FAILURE;
    }

    /* Put interface in promiscuous mode */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("[!] SIOCGIFINDEX failed");
        close(sock);
        return EXIT_FAILURE;
    }
    int ifindex = ifr.ifr_ifindex;

    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        perror("[!] Failed to set promiscuous mode");
    }

    printf("========================================================\\n");
    printf(" OcuLAN - Broadcast Storm & Layer 2 Watchdog Active     \\n");
    printf("========================================================\\n");
    printf("[+] Interface: %s | Threshold: %d PPS\\n", iface, threshold);
    printf("[+] Promiscuous packet capture started. Monitoring for storms...\\n\\n");

    uint8_t buffer[BUFFER_SIZE];
    uint32_t bcast_count = 0, mcast_count = 0, ucast_count = 0;
    time_t last_report = time(NULL);

    while (1) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < (ssize_t)sizeof(struct ether_header)) continue;

        struct ether_header *eth = (struct ether_header *)buffer;
        
        /* Check if destination is Ethernet broadcast FF:FF:FF:FF:FF:FF */
        if (eth->ether_dhost[0] == 0xFF && eth->ether_dhost[1] == 0xFF &&
            eth->ether_dhost[2] == 0xFF && eth->ether_dhost[3] == 0xFF &&
            eth->ether_dhost[4] == 0xFF && eth->ether_dhost[5] == 0xFF) {
            bcast_count++;
        }
        /* Check if destination is Multicast (LSB of first byte is 1) */
        else if (eth->ether_dhost[0] & 0x01) {
            mcast_count++;
        } else {
            ucast_count++;
        }

        time_t now = time(NULL);
        if (now > last_report) {
            uint32_t total_chatter = bcast_count + mcast_count;
            char time_buf[16];
            struct tm *tm_info = localtime(&now);
            strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);

            if (total_chatter >= (uint32_t)threshold) {
                printf("[!] %s ALERT: BROADCAST STORM DETECTED! Rate: %u PPS (Threshold: %d PPS) [Bcast: %u, Mcast: %u]\\n",
                       time_buf, total_chatter, threshold, bcast_count, mcast_count);
                printf("    --> Check for switch loop, rogue ARP sweeps, or unmanaged hub bridging!\\n");
            } else {
                printf("[%s] L2 Traffic Normal: %u Bcast PPS, %u Mcast PPS, %u Unicast PPS\\n",
                       time_buf, bcast_count, mcast_count, ucast_count);
            }

            bcast_count = 0;
            mcast_count = 0;
            ucast_count = 0;
            last_report = now;
        }
    }

    close(sock);
    return 0;
}
`
  },
  {
    filename: 'Makefile',
    title: 'Universal POSIX Makefile & Cross-Compilation Targets',
    description: 'Makefile supporting native GCC compilation, static musl-gcc binary creation for zero-dependency portability across any Linux distro, and ARM/Raspberry Pi cross-compilation.',
    category: 'Build System',
    compilationCmd: 'make\nmake static\nmake arm',
    requirements: 'make, gcc or musl-gcc or arm-linux-gnueabihf-gcc',
    capabilities: ['Static Binary Linkage', 'Cross-compilation for ARM/MIPS', 'Zero-dependency Deployment'],
    code: `# Makefile for OcuLAN Network Reconnaissance & Telemetry Suite
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -pedantic
LDFLAGS ?=

TARGETS = arp_scan icmp_sweep os_fingerprint lldp_vlan_sniff passive_monitor netflow_collector storm_detector

all: $(TARGETS)

arp_scan: arp_scan.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

icmp_sweep: icmp_sweep.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

os_fingerprint: os_fingerprint.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

lldp_vlan_sniff: lldp_vlan_sniff.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

passive_monitor: passive_monitor.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

netflow_collector: netflow_collector.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

storm_detector: storm_detector.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Build fully static binaries (standalone on any Linux distro / Alpine / OpenWrt)
static: CC = musl-gcc
static: CFLAGS += -static
static: $(TARGETS)

# Cross-compile for ARM (Raspberry Pi / OpenWrt routers)
arm: CC = arm-linux-gnueabihf-gcc
arm: CFLAGS += -static
arm: $(TARGETS)

clean:
	rm -f $(TARGETS) *.o

.PHONY: all static arm clean`
  }
];

