#include <linux/module.h>
#include <linux/platform_device.h>
#include <asm/io.h>
#include <linux/irqchip/arm-gic.h>
#include <asm/smp.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>
// 在文件开头的包含部分添加：
#include <linux/io.h>
#include <asm/cacheflush.h>      // 添加：缓存刷新函数
#include <linux/dma-mapping.h>   // 添加：DMA相关
#include <asm/barrier.h>         // 添加：内存屏障


/* TX: 主控 -> 组网 (0x3800xxxx) */
#define TX_BASE_ADDR          0x38000000  // TX基地址
#define TX_NET_IP_ADDR        (TX_BASE_ADDR + 0x00)  // 发送数据IP地址
#define TX_NET_NODE_ID        (TX_BASE_ADDR + 0x04)  // 发送数据节点号
#define TX_NET_IP_LEN         (TX_BASE_ADDR + 0x08)  // 发送长度
#define TX_TEST_FREQ_ADDR     (TX_BASE_ADDR + 0x0C)  // 测试信号频率
#define TX_TEST_ENABLE_ADDR   (TX_BASE_ADDR + 0x10)  // 测试信号使能
#define TX_FIXED_FREQ_ADDR    (TX_BASE_ADDR + 0x14)  // 定频频率
#define TX_NET_TEST_ADDR      (TX_BASE_ADDR + 0x18)  // 组网数据发送测试
#define TX_LOOPBACK_ADDR      (TX_BASE_ADDR + 0x1C)  // 数据自回环
#define TX_IQ_SWAP_ADDR       (TX_BASE_ADDR + 0x20)  // 接收基带IQ对调
#define TX_ATTEN_ADDR         (TX_BASE_ADDR + 0x24)  // 发射衰减系数
#define IP_TX_RAM_ADDR        0x38001000  // 数据首地址 (4K)
/* 控制寄存器地址 - 用于区分UDP数据和控制数据 */
#define CTRL_REG_ADDR         0x38005000  // 控制寄存器地址
/* RX: 组网 -> 主控 (0x3900xxxx) */
#define RX_NET_IP_ADDR        0x39000000  // 接收数据IP地址
#define RX_NET_NODE_ID        0x39000004  // 接收数据节点号
#define RX_NET_IP_LEN         0x39000008  // 接收长度
#define IP_RX_RAM_ADDR        0x39001000  // 数据首地址 (4K)
/* 监测数据地址 */
#define CH_TEMP_ADDR          0x3900000C  // 信道模块温度
/* 中断和大小定义 */
#define AMP_SGI_TX            15          // CPU0 -> CPU1 中断
#define AMP_SGI_RX            14          // CPU1 -> CPU0 中断
#define MAX_PAYLOAD_SIZE      4096        // 4K 数据区大小

/*
 * 业务数据(射频链路)最大承载长度。
 * 你们希望把多个小IP包聚合后一次写共享内存，且总长度不超过 640 字节。
 * 这里在驱动侧做一次硬限制，避免用户态误发超限帧导致 CPU1/射频侧异常。
 */

/* 控制帧结构（与用户程序一致） */
#pragma pack(push, 1)
struct control_frame {
    uint16_t frame_header;          // 帧头 0xF00F
    uint8_t  frame_type;            // 帧类型 0x01
    uint8_t  dst_addr;              // 目的地址（节点号）
    uint32_t frame_seq;             // 帧序列号
    uint32_t test_freq;             // 测试信号频率
    uint32_t test_enable;           // 测试信号使能
    uint32_t fixed_freq;            // 定频频率
    uint32_t net_test;              // 组网数据发送测试
    uint32_t loopback;              // 数据自回环
    uint32_t iq_swap;               // 接收基带IQ对调
    uint32_t attenuation;           // 发射衰减系数（新增）
    uint16_t frame_tail;            // 帧尾 0xE00E
};

#pragma pack(pop)

/* 用户态消息结构 */
struct amp_net_msg {
    u32 ip;                         // 目标IP地址
    u32 node_id;                    // 目标节点号
    u32 len;                        // 数据长度
    u8  data_type;                  // 数据类型: 0-UDP数据, 1-控制数据
    u8  data[MAX_PAYLOAD_SIZE];     // 数据内容
};

/* RX缓存：CPU1 -> CPU0 的数据先落在这里，用户态再read()取走 */
static struct amp_net_msg rx_msg;
static size_t rx_msg_bytes;
static atomic_t rx_pending = ATOMIC_INIT(0);  // 防重入/丢包保护：1表示有包未读
static wait_queue_head_t rx_wq;

/* 共享内存虚拟地址映射 */
static void __iomem *tx_ip_addr;         // 发送IP地址
static void __iomem *tx_node_id;         // 发送节点号
static void __iomem *tx_len;             // 发送长度
static void __iomem *tx_data_addr;       // 发送数据区

/* 控制参数寄存器映射 */
static void __iomem *tx_test_freq;      // 测试信号频率
static void __iomem *tx_test_enable;    // 测试信号使能
static void __iomem *tx_fixed_freq;     // 定频频率
static void __iomem *tx_net_test;       // 组网数据发送测试
static void __iomem *tx_loopback;       // 数据自回环
static void __iomem *tx_iq_swap;        // 接收基带IQ对调
static void __iomem *tx_atten;          // 发射衰减系数
static void __iomem *ctrl_reg;          // 控制寄存器
static void __iomem *rx_ip_addr;        // 接收IP地址
static void __iomem *rx_node_id;        // 接收节点号
static void __iomem *rx_len;            // 接收长度
static void __iomem *rx_data_addr;      // 接收数据区


/******************/
/* 监测数据地址映射 */
/******************/
static void __iomem *ch_temp_addr;      // 信道温度


/*****************************************/
/* 控制寄存器操作 - 按照协议：写入共享内存后置1 */
/*****************************************/
static void set_udp_data_enable(void)
{
    u8 reg_val;
//    if (!ctrl_reg)
//        return;
    
    reg_val = readb(ctrl_reg);
    /* bit0=UDP, bit1=CTRL: 设置UDP时要清掉CTRL位，避免两位同时为1 */
    reg_val = (reg_val & ~0x02) | 0x01;
    writeb(reg_val, ctrl_reg);
    wmb();
    //pr_info("Set control reg for UDP data: 0x%02X\n", reg_val);
}

static void set_control_data_enable(void)
{
    u8 reg_val;
//    if (!ctrl_reg)
//        return;
    reg_val = readb(ctrl_reg);
    /* bit0=UDP, bit1=CTRL: 设置CTRL时要清掉UDP位 */
    reg_val = (reg_val & ~0x01) | 0x02;
    writeb(reg_val, ctrl_reg);
    wmb();
    //pr_info("Set control reg for control data: 0x%02X\n", reg_val);
}


/**************/
/* 处理控制数据 */
/**************/
static int process_control_data(struct amp_net_msg *msg)
{
    struct control_frame *ctrl_frame;
    u16 frame_header, frame_tail;
    if (msg->len != sizeof(struct control_frame)) {
        //pr_err("Invalid control frame length: %u (expected %lu)\n",
        //       msg->len, sizeof(struct control_frame));
        return -EINVAL;
    }
    ctrl_frame = (struct control_frame *)msg->data;
    /* 检查帧头和帧尾 */
    frame_header = be16_to_cpu(ctrl_frame->frame_header);
    frame_tail = be16_to_cpu(ctrl_frame->frame_tail);
    if (frame_header != 0xF00F) {
        //pr_err("Invalid control frame header: 0x%04X\n", frame_header);
        return -EINVAL;
    }
    if (frame_tail != 0xE00E) {
        //pr_err("Invalid control frame tail: 0x%04X\n", frame_tail);
        return -EINVAL;
    }
    
    /* 提取目的地址作为节点号 */
    msg->node_id = ctrl_frame->dst_addr;

    /* 设置控制寄存器为控制数据模式 */
    set_control_data_enable();
    
    /* 写入控制参数到对应寄存器（注意字节序转换） */
    writel(be32_to_cpu(ctrl_frame->test_freq), tx_test_freq);      // 测试信号频率
    writel(be32_to_cpu(ctrl_frame->test_enable), tx_test_enable);  // 测试信号使能
    writel(be32_to_cpu(ctrl_frame->fixed_freq), tx_fixed_freq);    // 定频频率
    writel(be32_to_cpu(ctrl_frame->net_test), tx_net_test);        // 组网数据发送测试
    writel(be32_to_cpu(ctrl_frame->loopback), tx_loopback);        // 数据自回环
    writel(be32_to_cpu(ctrl_frame->iq_swap), tx_iq_swap);          // 接收基带IQ对调
    writel(be32_to_cpu(ctrl_frame->attenuation), tx_atten);        // 发射衰减系数
    
    wmb();  // 写内存屏障

    // 关键：写入完成后刷新缓存
    // 方法1：使用dsb指令确保写操作完成
    dsb(sy);
    // 方法2：刷新特定的缓存行
    __cpuc_flush_dcache_area(tx_test_freq, sizeof(struct control_frame));
    // 再次添加内存屏障

    /* 写入节点号和长度 */
//    writel(msg->node_id, tx_node_id);
//    writel(msg->len, tx_len);
//    wmb();
  
      pr_info("Control data sent:  seq=%u, tFreq=%u, tEn=%u, freq=%u, netT=%u, loopback=%u, iq_swap=%u, atten=%u\n",

           be32_to_cpu(ctrl_frame->frame_seq),
            be32_to_cpu(ctrl_frame->test_freq),
	    be32_to_cpu(ctrl_frame->test_enable),
            be32_to_cpu(ctrl_frame->fixed_freq),
	    be32_to_cpu(ctrl_frame->net_test),
	    be32_to_cpu(ctrl_frame->loopback),
	    be32_to_cpu(ctrl_frame->iq_swap),
	    be32_to_cpu(ctrl_frame->attenuation));
    return 0;
}


/**************/
/* 处理UDP数据 */
/**************/
static int process_udp_data(struct amp_net_msg *msg)
{
    /* 设置控制寄存器为UDP数据模式 */
    set_udp_data_enable();
    // 写入数据前添加内存屏障（可选）
    mb();  // 内存屏障，确保之前的写操作完成
    /* 根据数据类型处理 */
    /* 写入UDP数据到数据区 */
    if (msg->len > 0) {
        memcpy_toio(tx_data_addr, msg->data, msg->len);
        //pr_info("UDP data copied to shared memory: %u bytes\n", msg->len);
    }
    // 关键：写入完成后刷新缓存
    if (tx_data_addr) {
        // 方法1：使用dsb指令确保写操作完成
        dsb(sy);
        // 方法2：刷新特定的缓存行
        __cpuc_flush_dcache_area(tx_data_addr, msg->len);
    }
    // 再次添加内存屏障
    wmb();  // 写内存屏障
    
    /* 写入元数据 */
    writel(msg->ip, tx_ip_addr);
    //writel(msg->node_id, tx_node_id);
	writel(255, tx_node_id);
    wmb();
    writel(msg->len, tx_len);
    wmb();
    //pr_info("UDP data sent: node=%u, len=%u\n", msg->node_id, msg->len);
    return 0;
}


/****************/
/* 用户态写入接口 */
/****************/
static ssize_t amp_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
    struct amp_net_msg msg;
    int ret;
    //pr_info("amp_write called, len=%zu\n", len);
    /* 检查最小长度 */
    if (len < offsetof(struct amp_net_msg, data)) {
        //pr_err("Buffer too small: %zu < %lu\n", 
        //       len, offsetof(struct amp_net_msg, data));
        return -EINVAL;
    }
    
    /* 复制消息头部 */
    if (copy_from_user(&msg, buf, offsetof(struct amp_net_msg, data))) {
        //pr_err("copy_from_user for header failed\n");
        return -EFAULT;
    }
    
    /* 检查数据长度 */
    if (msg.len > MAX_PAYLOAD_SIZE) {
        //pr_err("Data length too large: %u > %d\n", msg.len, MAX_PAYLOAD_SIZE);
        return -EINVAL;
    }
    
    /* 复制数据部分 */
    if (msg.len > 0) {
        if (copy_from_user(msg.data,  buf + offsetof(struct amp_net_msg, data), msg.len)) {
            //pr_err("copy_from_user for data failed\n");
            return -EFAULT;
        }
    }

    /* 检查共享内存映射 */
    if (!tx_ip_addr || !tx_node_id || !tx_len || !tx_data_addr || !ctrl_reg) {
        //pr_err("Shared memory not mapped\n");
        return -ENODEV;
    }
//    pr_info("Processing data: type=%s, node=%u, len=%u\n",msg.data_type == 0 ? "UDP" : "CTRL", msg.node_id, msg.len);
    if (msg.data_type == 0) {
        ret = process_udp_data(&msg);
    } else if (msg.data_type == 1) {
        ret = process_control_data(&msg);
    } else {
        //pr_err("Invalid data type: %u\n", msg.data_type);
        return -EINVAL;
    }
    if (ret) {
        return ret;
    }
	
	pr_info("TX: ip=%pI4 len=%u ctrl=%u target=%u sgi=%u\n",
			&msg.ip, msg.len, readl(ctrl_reg), 1, AMP_SGI_TX);


    /* 触发中断通知CPU1 */
    //pr_info("Triggering interrupt SGI_TX=%d to CPU1\n", AMP_SGI_TX);
    //gic_raise_softirq_fmsh(1, AMP_SGI_TX);
    gic_raise_softirq_fmsh(1, AMP_SGI_TX);
    return offsetof(struct amp_net_msg, data) + msg.len;
}



/****************************/
/* 用户态读取接口：读取CPU1回来的数据包 */
/****************************/
static ssize_t amp_read(struct file *file, char __user *buf, size_t len, loff_t *ppos)
{
    ssize_t ret;

    /* 阻塞等待：直到有数据包到来 */
    if (!(file->f_flags & O_NONBLOCK)) {
        ret = wait_event_interruptible(rx_wq, atomic_read(&rx_pending) != 0);
        if (ret)
            return ret;
    } else {
        if (atomic_read(&rx_pending) == 0)
            return -EAGAIN;
    }

    if (len < rx_msg_bytes)
        return -EINVAL;

    if (copy_to_user(buf, &rx_msg, rx_msg_bytes))
        return -EFAULT;

    atomic_set(&rx_pending, 0);
    return rx_msg_bytes;
}



/*****************************/
/* 软中断处理函数：CPU1通知CPU0 */
/*****************************/
static void cpu1_to_cpu0_handler(int ipinr, void *dev_id)
{
    u32 len, node_id, ip;
    //pr_info("CPU1->CPU0 interrupt received\n");
	
    /* 防重入保护 */
    if (atomic_cmpxchg(&rx_pending, 0, 1) != 0) {
        pr_warn("RX already pending, skipping\n");
        return;
    }
    if (!rx_len || !rx_node_id || !rx_ip_addr || !rx_data_addr) {
        //pr_err("RX memory not mapped\n");
        atomic_set(&rx_pending, 0);
        return;
    }

    /* 读取元信息 */
    len = readl(rx_len);
    node_id = readl(rx_node_id);
    ip = readl(rx_ip_addr);
    rmb();
    //pr_info("RX metadata: len=%u, node_id=%u, ip=0x%08X\n", len, node_id, ip);
    if (len > MAX_PAYLOAD_SIZE) {
        //pr_err("Invalid length: %u > %d\n", len, MAX_PAYLOAD_SIZE);
        atomic_set(&rx_pending, 0);
        return;
    }

    /* 组装一条发给用户态的消息（read()取走后再清 pending） */
    memset(&rx_msg, 0, sizeof(rx_msg));
    rx_msg.data_type = 0; /* 目前RX侧只回传数据类（业务/隧道IP包） */
    rx_msg.ip = ip;
    rx_msg.node_id = node_id;
    rx_msg.len = len;
    if (len > 0)
        memcpy_fromio(rx_msg.data, rx_data_addr, len);

    rx_msg_bytes = offsetof(struct amp_net_msg, data) + len;
    wake_up_interruptible(&rx_wq);
}


/****************/
/* 文件操作结构体 */
/****************/
static const struct file_operations amp_fops = {
    .owner = THIS_MODULE,
    .write = amp_write,
    .read = amp_read,
};


/****************/
/* Misc设备结构体 */
/****************/
static struct miscdevice amp_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "amp_ipi",
    .fops = &amp_fops,
};


/****************/
/* 驱动probe函数 */
/****************/
static int zynq_amp_probe(struct platform_device *pdev)
{
    int ret;
    //pr_info("zynq_amp_probe called\n");
    /* 映射TX共享内存 */
    tx_ip_addr = ioremap_nocache(TX_NET_IP_ADDR, 4);
    tx_node_id = ioremap_nocache(TX_NET_NODE_ID, 4);
    tx_len = ioremap_nocache(TX_NET_IP_LEN, 4);
    tx_data_addr = ioremap_nocache(IP_TX_RAM_ADDR, MAX_PAYLOAD_SIZE);
    /* 映射控制参数寄存器 */
    tx_test_freq = ioremap_nocache(TX_TEST_FREQ_ADDR, 4);
    tx_test_enable = ioremap_nocache(TX_TEST_ENABLE_ADDR, 4);
    tx_fixed_freq = ioremap_nocache(TX_FIXED_FREQ_ADDR, 4);
    tx_net_test = ioremap_nocache(TX_NET_TEST_ADDR, 4);
    tx_loopback = ioremap_nocache(TX_LOOPBACK_ADDR, 4);
    tx_iq_swap = ioremap_nocache(TX_IQ_SWAP_ADDR, 4);
    tx_atten = ioremap_nocache(TX_ATTEN_ADDR, 4);
    /* 映射控制寄存器 */
    ctrl_reg = ioremap_nocache(CTRL_REG_ADDR, 4);
    /* 映射RX共享内存 */
    rx_ip_addr = ioremap_nocache(RX_NET_IP_ADDR, 4);
    rx_node_id = ioremap_nocache(RX_NET_NODE_ID, 4);
    rx_len = ioremap_nocache(RX_NET_IP_LEN, 4);
    rx_data_addr = ioremap_nocache(IP_RX_RAM_ADDR, MAX_PAYLOAD_SIZE);
    /* 映射ADC监测数据地址 */
    ch_temp_addr = ioremap_nocache(CH_TEMP_ADDR, 4);
    /* 检查映射是否成功 */
    if (!tx_ip_addr || !tx_node_id || !tx_len || !tx_data_addr || !ctrl_reg || !tx_test_freq || !tx_test_enable ||	!tx_fixed_freq ||
		!tx_net_test || !tx_loopback || !tx_iq_swap || !tx_atten || !rx_ip_addr || !rx_node_id || !rx_len || !rx_data_addr) {
        //pr_err("Failed to ioremap shared memory\n");
        return -ENOMEM;
    }

    /* 初始化控制寄存器为0x00（两位都置0） */
    writeb(0x00, ctrl_reg);
    wmb();

    /* 初始化RX等待队列（用户态read()阻塞等待CPU1->CPU0数据） */
    init_waitqueue_head(&rx_wq);
    atomic_set(&rx_pending, 0);
   
    /* 注册软中断处理函数 */
    ret = set_ipi_handler(AMP_SGI_RX, cpu1_to_cpu0_handler, NULL);
    if (ret) {
        //pr_err("set_ipi_handler(%d) failed: %d\n", AMP_SGI_RX, ret);
        goto error;
    }
    
    /* 注册misc设备 */
    ret = misc_register(&amp_miscdev);
    if (ret) {
        //pr_err("Misc register failed: %d\n", ret);
        goto error;
    }
    
    //pr_info("AMP driver loaded successfully\n");
    //pr_info("Device node: /dev/%s\n", amp_miscdev.name);
    return 0;
    
error:
    
    /* 释放所有映射的内存 */
    if (tx_ip_addr) iounmap(tx_ip_addr);
    if (tx_node_id) iounmap(tx_node_id);
    if (tx_len) iounmap(tx_len);
    if (tx_data_addr) iounmap(tx_data_addr);
    if (ctrl_reg) iounmap(ctrl_reg);
    if (tx_test_freq) iounmap(tx_test_freq);
    if (tx_test_enable) iounmap(tx_test_enable);
    if (tx_fixed_freq) iounmap(tx_fixed_freq);
    if (tx_net_test) iounmap(tx_net_test);
    if (tx_loopback) iounmap(tx_loopback);
    if (tx_iq_swap) iounmap(tx_iq_swap);
    if (tx_atten) iounmap(tx_atten);
    if (rx_ip_addr) iounmap(rx_ip_addr);
    if (rx_node_id) iounmap(rx_node_id);
    if (rx_len) iounmap(rx_len);
    if (rx_data_addr) iounmap(rx_data_addr);
    if (ch_temp_addr) iounmap(ch_temp_addr);
    return ret;
}


/*****************/
/* 驱动remove函数 */
/*****************/
static int zynq_amp_remove(struct platform_device *pdev)
{
    //pr_info("zynq_amp_remove called\n");
    /* 清理软中断 */
    clear_ipi_handler(AMP_SGI_RX);
    
    /* 注销misc设备 */
    misc_deregister(&amp_miscdev);
    
    /* 释放所有内存映射 */
    if (tx_ip_addr) iounmap(tx_ip_addr);
    if (tx_node_id) iounmap(tx_node_id);
    if (tx_len) iounmap(tx_len);
    if (tx_data_addr) iounmap(tx_data_addr);
    if (ctrl_reg) iounmap(ctrl_reg);
    if (tx_test_freq) iounmap(tx_test_freq);
    if (tx_test_enable) iounmap(tx_test_enable);
    if (tx_fixed_freq) iounmap(tx_fixed_freq);
    if (tx_net_test) iounmap(tx_net_test);
    if (tx_loopback) iounmap(tx_loopback);
    if (tx_iq_swap) iounmap(tx_iq_swap);
    if (tx_atten) iounmap(tx_atten);
    if (rx_ip_addr) iounmap(rx_ip_addr);
    if (rx_node_id) iounmap(rx_node_id);
    if (rx_len) iounmap(rx_len);
    if (rx_data_addr) iounmap(rx_data_addr);
    if (ch_temp_addr) iounmap(ch_temp_addr);
    //pr_info("AMP driver removed\n");
    return 0;
}


/**************/
/* 设备树匹配表 */
/**************/
static const struct of_device_id amp_of_match[] = {
    { .compatible = "xlnx,zynq-amp" },
    { /* Sentinel */ }
};
MODULE_DEVICE_TABLE(of, amp_of_match);


/****************/
/* 平台驱动结构体 */
/****************/
static struct platform_driver zynq_amp_driver = {
    .driver = {
        .name = "zynq_amp",
        .of_match_table = amp_of_match,
        .owner = THIS_MODULE,
    },
    .probe = zynq_amp_probe,
    .remove = zynq_amp_remove,
};

module_platform_driver(zynq_amp_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XuShengQiao");
MODULE_DESCRIPTION("AMP IPC Driver with Updated Protocol Support");
