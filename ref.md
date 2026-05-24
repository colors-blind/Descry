# Descry 重构思路文档

## 背景

原代码写于 2002 年，依赖 libnet 1.x 和当时的 pcap API，使用了大量非标准类型（`u_char`, `u_short`, `u_long`, `u_int32_t`）和已废弃/不安全的函数。目标是将其改造为可在现代 Linux 下以 C99 标准编译的代码。

## 重构目标

1. **C99 标准合规**
2. **移除不安全函数**
3. **使用现代 API**
4. **移除 libnet 依赖**（只保留 pcap 依赖）

---

## 具体改动

### 1. 头文件 (descry.h)

| 改动项 | 旧代码 | 新代码 |
|--------|--------|--------|
| 标准类型 | `u_char`, `u_short`, `u_long` | `uint8_t`, `uint16_t`, `uint32_t` (stdint.h) |
| 布尔类型 | 整数 0/1 | `bool` (stdbool.h) |
| 头文件 | `#include <libnet.h>` | `#include <netinet/ip.h>` + `<netinet/tcp.h>` + `<arpa/inet.h>` |
| 节点删除标记 | `(int)ptr == CON_REMOVED` 指针强转整数比较 | `bool removed` 字段 |
| Include guard | 无 | `#ifndef DESCRY_H` |
| 函数签名 | K&R 风格隐式 int、`char *` 参数 | 显式 `const` 限定、`void` 参数列表 |
| 宏安全性 | `SET_STATE` 无 do-while 包裹 | 用 `do { ... } while(0)` 包裹 |
| TCP 标志 | 依赖 libnet 的 `TH_SYN` 等 | 自定义 `TCP_FLAG_*` 宏 |
| IP/TCP 头结构 | `struct libnet_ipv4_hdr` / `struct libnet_tcp_hdr` | 标准 `struct ip` / `struct tcphdr` |

### 2. 源文件 (descry.c)

#### 不安全函数替换

| 旧函数 | 新函数 | 说明 |
|--------|--------|------|
| `strcpy(buf, ctime(&t))` | `localtime_r()` + `strftime()` | 消除缓冲区溢出风险，线程安全 |
| `malloc()` 未清零 | `calloc()` | 防止读取未初始化内存 |
| `memset(key, NULL, ...)` | `memset(key, 0, ...)` | NULL 作为整数使用是 UB |
| `libnet_addr2name4()` | `inet_ntop()` | 标准 POSIX 函数，线程安全 |

#### 废弃 API 替换

| 旧 API | 新 API | 说明 |
|--------|--------|------|
| `pcap_lookupdev()` | `pcap_findalldevs()` + `pcap_freealldevs()` | pcap_lookupdev 自 libpcap 1.9 起废弃 |
| EOF 作为 getopt 终止 | `-1` | POSIX 推荐写法 |

#### 类型安全修复

- `(int)ptr == CON_REMOVED`：将指针与整数比较是 UB → 改为 `node->removed` 布尔字段
- 三元运算符作左值（GCC 扩展，非标准）→ 拆分为显式 if-else 赋值
- `static u_char cleanup` 计数器会在 255 溢出 → 改为 `unsigned int`
- pcap callback 的 `u_char *packet` → `const uint8_t *packet`

#### 资源管理修复

- `descry_destroy()` 原来是空函数 → 现在正确释放 pcap 和内存
- `pcap_compile()` 后添加 `pcap_freecode()` 释放 BPF 程序
- `descry_init()` 失败路径增加资源回收
- `pt_insert()` 失败时释放已分配的 connection

#### 其他改善

- TCP flags 通过直接读偏移 13 字节获取，避免跨平台 `struct tcphdr` 字段命名差异
- 移除 `#include <libnet.h>` 整体依赖
- `get_time()` 输出格式保持一致（`Mon DD HH:MM:SS`）

---

## 编译方式

```bash
gcc -std=c99 -Wall -Wextra -pedantic -o descry descry.c -lpcap
```

如果系统 pcap 头文件不在默认路径：

```bash
gcc -std=c99 -Wall -Wextra -pedantic \
    -I/usr/include/pcap \
    -o descry descry.c -lpcap
```

## 运行方式

```bash
# 监听指定网卡（需要 root 或 CAP_NET_RAW）
sudo ./descry -i eth0

# 读取 tcpdump 抓包文件
./descry -f capture.pcap

# 监控同网段所有主机 + 输出到 syslog
sudo ./descry -i eth0 -a -s
```

## 遗留事项

- patricia trie 的遍历/删除逻辑在并发场景下不安全，如需多线程使用需加锁
- `pt_walk_r` 仍使用递归，深度取决于 trie 规模，极端情况可能栈溢出
- `descry_destroy()` 未递归释放 trie 所有节点（原代码即如此），完整实现需遍历整棵树
