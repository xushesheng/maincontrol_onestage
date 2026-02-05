#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <pthread.h>
#include <poll.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

/*
 * user_amp.c
 *
 * 作用：
 * - CPU0：从 TUN(rf0) 读出要跨板卡链路的 IPv4 包，经 /dev/amp_ipi 发给 CPU1。
 * - CPU0：从 /dev/amp_ipi 收到对端发来的数据，再写回 TUN，让内核继续路由到 eth1。
 * - 控制面：用 pcap 抓 eth1 上的控制 UDP(3409)，按原协议写到 /dev/amp_ipi。
 *
 * 数据面优化：
 * - 小包聚合：把多个“小IP包”打包成一个 <= 640B 的批帧(AMPB)，减少 SGI/共享内存写次数。
 * - 大包直发：任何 > 640B 的 IP 包，不参与聚合，作为单独 IP 包直接发送（解除单包 640 限制）。
 * - ICMP/ping 快速通道：ICMP echo request/reply 不等待聚合窗口，尽快发出。
 */

#define AMP_DEV             "/dev/amp_ipi"
#define CAP_IFACE           "eth1"
#define CTRL_UDP_PORT       3409

#define MAX_PAYLOAD_SIZE    4096

/* 聚合帧最大长度（只对“批帧 AMPB”限制 640，单包直发不受此限制） */
#define AMP_BATCH_MAX_BYTES 640
#define AMP_BATCH_MAGIC     "AMPB"
#define AMP_BATCH_VERSION   1

/* 聚合窗口：第一个包进入批次后，最多再等这么多 ms 看能不能凑更多包。
 * 调大：吞吐更好但交互/ ping RTT 更大；调小：时延更好但 SGI 次数更多。 */
#define AMP_BATCH_TIMEOUT_MS  96

/* ICMP/ping 快速通道开关 */
#define AMP_ICMP_FASTPATH   1

/* rf0 MTU：为了允许 >640 的 IP 包“单包直发”，这里不要再强制设成 600。
 * 如需限制请在系统脚本里按链路能力配置。 */
#define RF0_MTU             1500

/* 与驱动一致（保持你们已有字段语义） */
struct amp_net_msg {
    uint32_t ip;
    uint32_t node_id;
    uint32_t len;
    uint8_t  data_type; /* 0-数据, 1-控制 */
    uint8_t  data[MAX_PAYLOAD_SIZE];
};

/* 控制帧结构（保持你原协议） */
#pragma pack(push, 1)
typedef struct {
    uint16_t frame_header;
    uint8_t  frame_type;
    uint8_t  dst_addr;
    uint32_t frame_seq;
    uint32_t test_freq;
    uint32_t test_enable;
    uint32_t fixed_freq;
    uint32_t net_test;
    uint32_t loopback;
    uint32_t iq_swap;
    uint32_t attenuation;
    uint16_t frame_tail;
} control_frame_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint8_t  magic[4];
    uint8_t  version;
    uint8_t  flags;
    uint16_t count_be;
    uint32_t seq_be;
} amp_batch_hdr_t;
#pragma pack(pop)

typedef struct {
    uint8_t  buf[AMP_BATCH_MAX_BYTES];
    size_t   len;
    uint16_t count;
    uint32_t seq;
    uint32_t dst_ip; /* network byte order */
} batch_state_t;

static int amp_fd = -1;
static int tun_fd = -1;
static uint32_t remote_pc_addr = 0; /* network byte order */

static inline uint16_t read_be16_unaligned(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return ntohs(v);
}

static inline void write_be16_unaligned(uint8_t *p, uint16_t v)
{
    uint16_t t = htons(v);
    memcpy(p, &t, sizeof(t));
}

static inline void write_be32_unaligned(uint8_t *p, uint32_t v)
{
    uint32_t t = htonl(v);
    memcpy(p, &t, sizeof(t));
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return 0;
}

static int tun_alloc(const char *devname)
{
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, devname, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }
    return fd;
}

static int get_iface_ipv4(const char *ifname, struct in_addr *addr)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *addr = sin->sin_addr;
    close(fd);
    return 0;
}

static void run_cmd(const char *cmd)
{
    int rc = system(cmd);
    if (rc != 0)
        fprintf(stderr, "[WARN] cmd failed (%d): %s\n", rc, cmd);
}

static void setup_gateway_rules(void)
{
    struct in_addr local_ip;
    if (get_iface_ipv4(CAP_IFACE, &local_ip) != 0) {
        fprintf(stderr, "[ERROR] cannot get %s IPv4 address\n", CAP_IFACE);
        return;
    }

    uint8_t *p = (uint8_t *)&local_ip.s_addr; /* network order */
    uint8_t last = p[3];

    const char *remote_pc = NULL;
    const char *rf_ip = NULL;

    if (last == 13) {
        remote_pc = "192.168.1.15"; /* PC B */
        rf_ip = "10.255.0.1/30";
    } else if (last == 12) {
        remote_pc = "192.168.1.20"; /* PC A */
        rf_ip = "10.255.0.2/30";
    } else {
        fprintf(stderr, "[WARN] unexpected %s IP=%s, default remote_pc=192.168.1.15, rf_ip=10.255.0.1/30\n",
                CAP_IFACE, inet_ntoa(local_ip));
        remote_pc = "192.168.1.15";
        rf_ip = "10.255.0.1/30";
    }

    remote_pc_addr = inet_addr(remote_pc);
    if (remote_pc_addr == INADDR_NONE) {
        fprintf(stderr, "[ERROR] bad remote_pc ip: %s\n", remote_pc);
        exit(1);
    }

    run_cmd("sysctl -w net.ipv4.ip_forward=1 >/dev/null");
    run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null");
    run_cmd("sysctl -w net.ipv4.conf.eth1.rp_filter=0 >/dev/null");

    run_cmd("sysctl -w net.ipv4.conf.eth1.proxy_arp=1 >/dev/null");
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip neigh add proxy %s dev %s 2>/dev/null || true", remote_pc, CAP_IFACE);
        run_cmd(cmd);
    }

    run_cmd("ip link set rf0 up 2>/dev/null || true");
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip link set rf0 mtu %d 2>/dev/null || true", RF0_MTU);
        run_cmd(cmd);
    }
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip addr add %s dev rf0 2>/dev/null || true", rf_ip);
        run_cmd(cmd);
    }
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip route add %s/32 dev rf0 2>/dev/null || true", remote_pc);
        run_cmd(cmd);
    }

    printf("[INFO] gateway enabled on %s=%s, proxy_arp for %s, route %s/32 -> rf0\n",
           CAP_IFACE, inet_ntoa(local_ip), remote_pc, remote_pc);
}

static void batch_reset(batch_state_t *b)
{
    uint32_t seq = b->seq;
    memset(b, 0, sizeof(*b));
    b->seq = seq;

    amp_batch_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, AMP_BATCH_MAGIC, 4);
    hdr.version = AMP_BATCH_VERSION;
    hdr.flags = 0;
    hdr.count_be = htons(0);
    hdr.seq_be = htonl(b->seq);

    memcpy(b->buf, &hdr, sizeof(hdr));
    b->len = sizeof(hdr);
    b->count = 0;
    b->dst_ip = 0;
}

static int batch_append(batch_state_t *b, const uint8_t *pkt, size_t pkt_len, uint32_t dst_ip)
{
    if (pkt_len > 0xFFFF) return -1;
    if (b->len + 2 + pkt_len > AMP_BATCH_MAX_BYTES) return -2;

    if (b->count == 0)
        b->dst_ip = dst_ip;

    write_be16_unaligned(b->buf + b->len, (uint16_t)pkt_len);
    b->len += 2;
    memcpy(b->buf + b->len, pkt, pkt_len);
    b->len += pkt_len;

    b->count++;
    write_be16_unaligned(b->buf + offsetof(amp_batch_hdr_t, count_be), b->count);
    write_be32_unaligned(b->buf + offsetof(amp_batch_hdr_t, seq_be), b->seq);
    return 0;
}

static int amp_send_msg(uint32_t dst_ip, const uint8_t *payload, size_t len)
{
    if (len > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "[ERROR] payload too large: %zu > %d\n", len, MAX_PAYLOAD_SIZE);
        return -1;
    }

    struct amp_net_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.data_type = 0;
    msg.ip = dst_ip;
    msg.node_id = 255;
    msg.len = (uint32_t)len;
    memcpy(msg.data, payload, len);

    ssize_t w = write(amp_fd, &msg, offsetof(struct amp_net_msg, data) + msg.len);
    if (w < 0) {
        perror("write(amp)");
        return -1;
    }
    return 0;
}

static int amp_flush_batch_if_any(batch_state_t *b)
{
    if (b->count == 0)
        return 0;

    /* 如果批次里只有 1 个子包，为减少头开销，直接发原始 IP 包 */
    if (b->count == 1) {
        size_t off = sizeof(amp_batch_hdr_t);
        if (b->len < off + 2) {
            batch_reset(b);
            return -1;
        }
        uint16_t l = read_be16_unaligned(b->buf + off);
        if (off + 2 + l > b->len) {
            batch_reset(b);
            return -1;
        }
        (void)amp_send_msg(b->dst_ip, b->buf + off + 2, l);
        b->seq++;
        batch_reset(b);
        return 0;
    }

    (void)amp_send_msg(b->dst_ip, b->buf, b->len);
    b->seq++;
    batch_reset(b);
    return 0;
}

static int is_icmp_ping_fastpath(const uint8_t *pkt, size_t len)
{
    if (len < sizeof(struct iphdr)) return 0;
    const struct iphdr *ip = (const struct iphdr *)pkt;
    if (ip->version != 4) return 0;
    size_t ihl = (size_t)ip->ihl * 4;
    if (ihl < sizeof(struct iphdr) || len < ihl + sizeof(struct icmphdr)) return 0;
    if (ip->protocol != IPPROTO_ICMP) return 0;

    const struct icmphdr *ic = (const struct icmphdr *)(pkt + ihl);
    if (ic->type == ICMP_ECHO || ic->type == ICMP_ECHOREPLY)
        return 1;
    return 0;
}

static void *tun_to_amp_thread(void *arg)
{
    (void)arg;
    uint8_t buf[MAX_PAYLOAD_SIZE];

    batch_state_t batch;
    memset(&batch, 0, sizeof(batch));
    batch_reset(&batch);

    (void)set_nonblock(tun_fd);

    while (1) {
        int timeout_ms = (batch.count == 0) ? -1 : AMP_BATCH_TIMEOUT_MS;
        struct pollfd pfd = { .fd = tun_fd, .events = POLLIN };
        int prc = poll(&pfd, 1, timeout_ms);
        if (prc < 0) {
            if (errno == EINTR) continue;
            perror("poll(tun)");
            break;
        }

        if (prc == 0) {
            /* 聚合窗口超时：发掉当前批次 */
            (void)amp_flush_batch_if_any(&batch);
            continue;
        }

        /* 尽可能把当前可读的数据读空（non-blocking），提高聚合命中率 */
        while (1) {
            ssize_t n = read(tun_fd, buf, sizeof(buf));
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                if (errno == EINTR)
                    continue;
                perror("read(tun)");
                goto out;
            }
            if (n == 0)
                break;

            if ((size_t)n < sizeof(struct iphdr))
                continue;
            struct iphdr *ip = (struct iphdr *)buf;
            if (ip->version != 4)
                continue;
            if (ip->daddr != remote_pc_addr)
                continue;

            size_t pkt_len = (size_t)n;
            uint32_t dst_ip = ip->daddr;

#if AMP_ICMP_FASTPATH
            int is_ping = is_icmp_ping_fastpath(buf, pkt_len);
#else
            int is_ping = 0;
#endif

            /* ====== 解除单包 640B 限制：>640 直接单包直发 ====== */
            if (pkt_len > AMP_BATCH_MAX_BYTES) {
                (void)amp_flush_batch_if_any(&batch);
                (void)amp_send_msg(dst_ip, buf, pkt_len);
                continue;
            }

            /* 对于 <=640 的包，仍要考虑批帧头/长度字段的开销：塞不进批帧就单包直发 */
            size_t agg_overhead = sizeof(amp_batch_hdr_t) + 2; /* 若批帧为空，只装一个子包的最小开销 */
            if (pkt_len + agg_overhead > AMP_BATCH_MAX_BYTES) {
                (void)amp_flush_batch_if_any(&batch);
                (void)amp_send_msg(dst_ip, buf, pkt_len);
                continue;
            }

            /* ping 快速通道：不等待聚合窗口。
             * 优先尝试把 ping 塞进当前批次，然后立刻 flush（尽量不额外增加 SGI 次数）。 */
            if (is_ping) {
                int appended = 0;
                if (batch.count == 0 || batch.dst_ip == dst_ip) {
                    if (batch_append(&batch, buf, pkt_len, dst_ip) == 0)
                        appended = 1;
                }
                if (!appended) {
                    (void)amp_flush_batch_if_any(&batch);
                    (void)amp_send_msg(dst_ip, buf, pkt_len);
                } else {
                    (void)amp_flush_batch_if_any(&batch);
                }
                continue;
            }

            /* 普通小包：按目的IP聚合。
             * 若目的IP改变，先 flush 再开始新批次。 */
            if (batch.count > 0 && batch.dst_ip != dst_ip)
                (void)amp_flush_batch_if_any(&batch);

            int rc = batch_append(&batch, buf, pkt_len, dst_ip);
            if (rc == -2) {
                /* 空间不足：先 flush 再试一次；若还是不行就单包直发 */
                (void)amp_flush_batch_if_any(&batch);
                rc = batch_append(&batch, buf, pkt_len, dst_ip);
                if (rc != 0)
                    (void)amp_send_msg(dst_ip, buf, pkt_len);
            } else if (rc != 0) {
                (void)amp_flush_batch_if_any(&batch);
                (void)amp_send_msg(dst_ip, buf, pkt_len);
            }
        }
    }

out:
    (void)amp_flush_batch_if_any(&batch);
    return NULL;
}

static int tun_write_packet(int fd, const uint8_t *pkt, size_t len)
{
    while (1) {
        ssize_t w = write(fd, pkt, len);
        if (w == (ssize_t)len)
            return 0;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd p = { .fd = fd, .events = POLLOUT };
            (void)poll(&p, 1, 10);
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        return -1;
    }
}

static void *amp_to_tun_thread(void *arg)
{
    (void)arg;
    struct amp_net_msg msg;

    while (1) {
        ssize_t n = read(amp_fd, &msg, sizeof(msg));
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("read(amp)");
            break;
        }
        if ((size_t)n < offsetof(struct amp_net_msg, data))
            continue;
        if (msg.len == 0 || msg.len > MAX_PAYLOAD_SIZE)
            continue;

        /* 兼容：
         * - AMPB：拆包写回 TUN
         * - 否则：按单个原始 IP 包写回 TUN */
        if (msg.len >= sizeof(amp_batch_hdr_t) && memcmp(msg.data, AMP_BATCH_MAGIC, 4) == 0) {
            const amp_batch_hdr_t *hdr = (const amp_batch_hdr_t *)msg.data;
            if (hdr->version != AMP_BATCH_VERSION)
                continue;

            uint16_t count = ntohs(hdr->count_be);
            size_t off = sizeof(amp_batch_hdr_t);
            for (uint16_t i = 0; i < count; i++) {
                if (off + 2 > msg.len)
                    break;
                uint16_t l = read_be16_unaligned(msg.data + off);
                off += 2;
                if (off + l > msg.len)
                    break;
                (void)tun_write_packet(tun_fd, msg.data + off, l);
                off += l;
            }
        } else {
            (void)tun_write_packet(tun_fd, msg.data, msg.len);
        }
    }

    return NULL;
}

static int process_control_frame(uint8_t *udp_payload, int payload_len)
{
    if (payload_len != (int)sizeof(control_frame_t))
        return -1;

    control_frame_t ctrl_frame;
    memcpy(&ctrl_frame, udp_payload, sizeof(ctrl_frame));

    if (ntohs(ctrl_frame.frame_header) != 0xF00F) return -1;
    if (ntohs(ctrl_frame.frame_tail) != 0xE00E) return -1;

    struct amp_net_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.data_type = 1;
    msg.node_id = ctrl_frame.dst_addr;
    msg.ip = 0;
    msg.len = sizeof(ctrl_frame);
    memcpy(msg.data, &ctrl_frame, sizeof(ctrl_frame));

    ssize_t w = write(amp_fd, &msg, offsetof(struct amp_net_msg, data) + msg.len);
    if (w < 0)
        perror("write(amp ctrl)");
    return 0;
}

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;
    (void)header;

    /* 以太网头 14B */
    if (header->caplen < 14 + sizeof(struct iphdr))
        return;

    const struct iphdr *ip = (const struct iphdr *)(packet + 14);
    if (ip->version != 4)
        return;

    size_t ihl = (size_t)ip->ihl * 4;
    if (header->caplen < 14 + ihl + sizeof(struct udphdr))
        return;

    if (ip->protocol != IPPROTO_UDP)
        return;

    const struct udphdr *udp = (const struct udphdr *)((const uint8_t *)ip + ihl);
    uint16_t dst_port = ntohs(udp->dest);
    if (dst_port != CTRL_UDP_PORT)
        return;

    const uint8_t *payload = (const uint8_t *)(udp + 1);
    int payload_len = (int)ntohs(udp->len) - (int)sizeof(struct udphdr);
    if (payload_len <= 0)
        return;

    (void)process_control_frame((uint8_t *)payload, payload_len);
}

static void *pcap_control_thread(void *arg)
{
    (void)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(CAP_IFACE, 4096, 0, 10, errbuf);
    if (!handle) {
        fprintf(stderr, "[ERROR] pcap_open_live(%s) failed: %s\n", CAP_IFACE, errbuf);
        return NULL;
    }

    struct bpf_program fp;
    char filter_exp[128];
    snprintf(filter_exp, sizeof(filter_exp), "udp and dst port %d", CTRL_UDP_PORT);
    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "[ERROR] pcap filter failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    while (1) {
        int rc = pcap_dispatch(handle, 1, got_packet, NULL);
        if (rc < 0) {
            fprintf(stderr, "[ERROR] pcap_dispatch: %s\n", pcap_geterr(handle));
            break;
        }
    }

    pcap_close(handle);
    return NULL;
}

int main(void)
{
    amp_fd = open(AMP_DEV, O_RDWR);
    if (amp_fd < 0) {
        perror("open(" AMP_DEV ")");
        return 1;
    }

    tun_fd = tun_alloc("rf0");
    if (tun_fd < 0)
        return 1;

    setup_gateway_rules();

    pthread_t t1, t2, t3;
    if (pthread_create(&t1, NULL, tun_to_amp_thread, NULL) != 0) {
        perror("pthread_create(tun_to_amp)");
        return 1;
    }
    if (pthread_create(&t2, NULL, amp_to_tun_thread, NULL) != 0) {
        perror("pthread_create(amp_to_tun)");
        return 1;
    }
    if (pthread_create(&t3, NULL, pcap_control_thread, NULL) != 0) {
        perror("pthread_create(pcap_control)");
        return 1;
    }

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    return 0;
}
