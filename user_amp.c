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
    uint8_t  magic[4];      //AMPB
    uint8_t  version;		//1
    uint8_t  flags;			//0
    uint16_t count_be;		//子包数量
    uint32_t seq_be;		//序号
} amp_batch_hdr_t;
#pragma pack(pop)

typedef struct {
    uint8_t  buf[AMP_BATCH_MAX_BYTES];		//640字节缓冲区
    size_t   len;							//当前已写入长度
    uint16_t count;							//当前已写入子包数量
    uint32_t seq;							//批帧序号
    uint32_t dst_ip; 						//当前批次的目的IP地址
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

/*
 * 根据本板卡eth1 IP（192.168.1.13 / 192.168.1.12）推导：
 * - 要代理ARP的“远端PC IP”
 * - rf0地址
 */
static void setup_gateway_rules(void)
{
    struct in_addr local_ip;
    if (get_iface_ipv4(CAP_IFACE, &local_ip) != 0) {
        fprintf(stderr, "[ERROR] cannot get %s IPv4 address\n", CAP_IFACE);
        return;
    }

    uint8_t *p = (uint8_t *)&local_ip.s_addr; /* network order */
    /* local_ip.s_addr是网络序，逐字节拿出来没问题 */
    uint8_t last = p[3];

    const char *remote_pc = NULL;
    const char *rf_ip = NULL;

    if (last == 13) {
        /* 板卡A：192.168.1.13 连接 PC A(192.168.1.20)，要把发往PC B(192.168.1.15)的流量引到自己 */
        remote_pc = "192.168.1.15"; /* PC B */
        rf_ip = "10.255.0.1/30";
    } else if (last == 12) {
        /* 板卡B：192.168.1.12 连接 PC B(192.168.1.15)，要把发往PC A(192.168.1.20)的流量引到自己 */
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

    /* 让内核允许转发 */
    run_cmd("sysctl -w net.ipv4.ip_forward=1 >/dev/null");
    /* 避免反向路径过滤把转发包丢掉 */
    run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null");
    run_cmd("sysctl -w net.ipv4.conf.eth1.rp_filter=0 >/dev/null");

    /* proxy ARP：让PC把对端PC的ARP解析到本板卡MAC */
    run_cmd("sysctl -w net.ipv4.conf.eth1.proxy_arp=1 >/dev/null");
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip neigh add proxy %s dev %s 2>/dev/null || true", remote_pc, CAP_IFACE);
        run_cmd(cmd);
    }

    /* TUN口配置 */
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
        /* 把远端PC的/32路由导向rf0，使内核把这类包吐给TUN */
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ip route add %s/32 dev rf0 2>/dev/null || true", remote_pc);
        run_cmd(cmd);
    }

    printf("[INFO] gateway enabled on %s=%s, proxy_arp for %s, route %s/32 -> rf0\n",
           CAP_IFACE, inet_ntoa(local_ip), remote_pc, remote_pc);
}

/******
*初始化聚合帧
******/
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

/*
 *发送当前批次的所有数据
 */
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

/* 线程1：从TUN读取需要“跨射频”的IP包，写入驱动（-> CPU1 -> 对端） */
static void *tun_to_amp_thread(void *arg)
{
    (void)arg;
    uint8_t buf[MAX_PAYLOAD_SIZE];

    batch_state_t batch;																	//准备一个空帧
    memset(&batch, 0, sizeof(batch));                                                       //清零帧数据
    batch_reset(&batch);																	//初始化批次帧

    (void)set_nonblock(tun_fd);

    while (1) {
        int timeout_ms = (batch.count == 0) ? -1 : AMP_BATCH_TIMEOUT_MS;                    //batch 为空：timeout=-1;batch 非空：timeout=AMP_BATCH_TIMEOUT_MS
        struct pollfd pfd = { .fd = tun_fd, .events = POLLIN };                             //初始化poll阻塞，设置标识符为tun_fd,events为pollin可读
        int prc = poll(&pfd, 1, timeout_ms);                                                //阻塞pfd标识timeout_ms时间
        if (prc < 0) {                                                                      //>0表示pfd中准备好
            if (errno == EINTR) continue;
            perror("poll(tun)");
            break;
        }

        if (prc == 0) {                                                                     //表示pfd中tun_fd没有准备好读写或出错，当poll阻塞超时timeout
            /* 聚合窗口超时：发掉当前批次 */
            (void)amp_flush_batch_if_any(&batch);
            continue;
        }

        /* 尽可能把当前可读的数据读空（non-blocking），提高聚合命中率 */
        while (1) {
            ssize_t n = read(tun_fd, buf, sizeof(buf));                                     //从tun中取一个IP包
            if (n < 0) {                                                                    //报错
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                if (errno == EINTR)
                    continue;
                perror("read(tun)");
                goto out;
            }
            if (n == 0)//无数据
                break;

            if ((size_t)n < sizeof(struct iphdr))                                           //如果小于iphdr结构体长度
                continue;
            struct iphdr *ip = (struct iphdr *)buf;
            if (ip->version != 4)
                continue;
            if (ip->daddr != remote_pc_addr)                                                //确定目的IP为对端节点IP
                continue;

            size_t pkt_len = (size_t)n;                                                     //定义pkt_len设置为本条IP包长度
            uint32_t dst_ip = ip->daddr;                                                    //定义dst_ip赋值为当前IP包目的地址

#if AMP_ICMP_FASTPATH
            int is_ping = is_icmp_ping_fastpath(buf, pkt_len);                              //判断是否为ping包，是的话置is_ping为1
#else
            int is_ping = 0;
#endif

            /* ====== 解除单包 640B 限制：>640 直接单包直发 ====== */
            if (pkt_len > AMP_BATCH_MAX_BYTES) {                                            //如果当前包超过640B
                (void)amp_flush_batch_if_any(&batch);                                       //则先将之前存的batch发出
                (void)amp_send_msg(dst_ip, buf, pkt_len);                                   //再单独将本批次的IP包写入
                continue;
            }

            /* 对于 <=640 的包，仍要考虑批帧头/长度字段的开销：塞不进批帧就单包直发 */
            size_t agg_overhead = sizeof(amp_batch_hdr_t) + 2;                              /* 若批帧为空，只装一个子包的最小开销（包长+2） */
            if (pkt_len + agg_overhead > AMP_BATCH_MAX_BYTES) {                             //如果当前IP包长度加上另一最小帧大于640依旧
                (void)amp_flush_batch_if_any(&batch);                                       //则先将之前存的batch发出
                (void)amp_send_msg(dst_ip, buf, pkt_len);                                   //再单独将本批次的IP包写入
                continue;
            }

            /* ping 快速通道：不等待聚合窗口。
             * 优先尝试把 ping 塞进当前批次，然后立刻 flush（尽量不额外增加 SGI 次数）。 */
            if (is_ping) {                                                                  //如果当前IP包时ping包
                int appended = 0;                                                           //定义添加标识
                if (batch.count == 0 || batch.dst_ip == dst_ip) {                           //如果当前序列为空或者batch的目的IP与ping包一致
                    if (batch_append(&batch, buf, pkt_len, dst_ip) == 0)                    //如果添加成功
                        appended = 1;                                                       //添加标识置为1
                }
                if (!appended) {                                                            //如果添加标识还是0代表上一个if中添加ping包失败
                    (void)amp_flush_batch_if_any(&batch);                                   //那就先将存的batch发出
                    (void)amp_send_msg(dst_ip, buf, pkt_len);                               //再单独发出ping包
                } else {
                    (void)amp_flush_batch_if_any(&batch);                                   //如果前面添加成功，则直接发出整个batch
                }
                continue;
            }

            /* 普通小包：按目的IP聚合。
			
             * 若目的IP改变，先 flush 再开始新批次。 */
            if (batch.count > 0 && batch.dst_ip != dst_ip)                                  //当前IP包目的IP如果与存的batch不同
                (void)amp_flush_batch_if_any(&batch);                                       //则先发出存的batch
                                                                                            //否则如果这是batch的第一发或者目的IP一致则
            int rc = batch_append(&batch, buf, pkt_len, dst_ip);                            //定义rc为添加IP包进入batch函数的返回值
            if (rc == -2) {
                /* 空间不足：先 flush 再试一次；若还是不行就单包直发 */
                (void)amp_flush_batch_if_any(&batch);
                rc = batch_append(&batch, buf, pkt_len, dst_ip);                            //再次添加
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

/* 线程2：从驱动read()取出对端发来的IP包，写回TUN，让内核继续路由到eth1发给本地PC */
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
        /* 目前约定：驱动RX回来的都是数据类（data_type==0），控制数据仍走CPU0->CPU1方向即可 */

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

/*
控制数据发送函数
 */
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

/* 控制帧仍然用你原来的pcap方式截获（不影响路由数据面） */
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
