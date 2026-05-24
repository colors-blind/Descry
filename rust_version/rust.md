# Descry Rust 重构设计

## 概述

将 2002 年的 C 语言 TCP 端口扫描检测工具 Descry 重构为惯用 Rust 实现。

## 原始 C 代码分析

原始代码功能：
- 通过 libpcap 捕获网络包（支持 live capture 和 pcap 文件）
- BPF 过滤器只抓 SYN-ACK、FIN-ACK、RST 包
- 用手写 patricia trie 跟踪 TCP 连接状态
- 检测"全连接端口扫描"：建立连接后不发数据就立即关闭（sequence number delta <= 2）
- 定期清理过期的半开连接（超过 ~3.3 小时）

## 重构策略

### 数据结构替换

| C 原版 | Rust 版 | 理由 |
|--------|---------|------|
| 手写 patricia trie | `HashMap<ConnectionKey, ConnectionState>` | 标准库 HashMap O(1) 查找，代码量减少 90%，性能在此场景下足够 |
| `struct in_addr` + 手动 memcpy key | `Ipv4Addr` + derive Hash/Eq | 类型安全，零成本抽象 |
| `struct timeval` + 宏减法 | `std::time::Duration` | 原生支持算术运算 |
| getopt 手动解析 | clap derive | 声明式参数定义 |
| libnet 头部解析 | pnet packet | 零拷贝包解析 |
| syslog(3) | `syslog` crate + `log` facade | 统一日志接口 |

### 核心 Crate 选择

- **pcap** (v2): libpcap 的 Rust binding，API 接近原生但类型安全
- **pnet** (v0.35): 网络协议栈解析，替代 libnet 的头部结构定义
- **clap** (v4, derive): 命令行参数
- **chrono**: 时间格式化输出
- **log + syslog + env_logger**: 日志

### 架构变化

1. **连接跟踪**: 从 patricia trie 改为 HashMap，key 是 `(src_ip, src_port, dst_ip, dst_port)` 四元组
2. **过期清理**: 从递归遍历 trie 改为 `HashMap::retain()` 一行搞定
3. **内存管理**: 无 malloc/free，全部由所有权系统管理
4. **错误处理**: 用 `Option`/`expect` 替代 NULL 检查和返回码

## 检测逻辑（保持不变）

```
收到 SYN-ACK → 记录连接（偏向发起方视角，反转 src/dst）
收到 FIN-ACK/RST → 查找对应连接：
  - 找到 → 检查 seq delta，delta <= 2 说明没发数据 → 报告扫描
  - 没找到 → 尝试反向查找并删除
每 1000 个包 → 清理超时连接（>11800s）
```

## 编译与运行

```bash
cd rust_version
cargo build --release

# live capture (需要 root 或 CAP_NET_RAW)
sudo ./target/release/descry -i eth0

# 读取 pcap 文件
./target/release/descry -f capture.pcap

# 全网段监听 + syslog
sudo ./target/release/descry -i eth0 -a -s
```

## 命令行参数

```
Usage: descry [OPTIONS]

Options:
  -a, --all-hosts            Monitor all hosts (promiscuous mode)
  -i, --interface <NAME>     Network interface
  -f, --file <PATH>          Pcap capture file
  -s, --syslog               Log to syslog instead of stderr
  -h, --help                 Print help
  -V, --version              Print version
```

## 系统依赖

运行时需要 libpcap：
```bash
# Debian/Ubuntu
sudo apt install libpcap-dev

# Arch
sudo pacman -S libpcap
```
