use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use chrono::Local;
use clap::Parser;
use pcap::{Capture, Device};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};

const CLEANUP_INTERVAL: u32 = 1000;
const EXPIRE_SECONDS: u64 = 11800;

const BPF_FILTER: &str = "((tcp[13] & 0x12) == 0x12) || \
                           ((tcp[13] & 0x11) == 0x11) || \
                           ((tcp[13] & 0x14) == 0x14) || \
                           ((tcp[13] & 0x04) == 0x04)";

#[derive(Parser)]
#[command(name = "descry", version = "1.0", about = "TCP port scan detection tool")]
struct Args {
    /// Monitor all hosts in the same segment (promiscuous mode)
    #[arg(short = 'a', long)]
    all_hosts: bool,

    /// Network interface to capture on
    #[arg(short = 'i', long, conflicts_with = "file")]
    interface: Option<String>,

    /// Tcpdump capture file to read
    #[arg(short = 'f', long, conflicts_with = "interface")]
    file: Option<String>,

    /// Log to syslog instead of stderr
    #[arg(short = 's', long)]
    syslog: bool,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct ConnectionKey {
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
}

#[derive(Clone, Debug)]
struct ConnectionState {
    seq: u32,
    timestamp: Duration,
}

struct Descry {
    connections: HashMap<ConnectionKey, ConnectionState>,
    use_syslog: bool,
    cleanup_counter: u32,
    link_offset: usize,
}

impl Descry {
    fn new(use_syslog: bool, link_offset: usize) -> Self {
        Self {
            connections: HashMap::new(),
            use_syslog,
            cleanup_counter: 0,
            link_offset,
        }
    }

    fn process_packet(&mut self, header_ts: Duration, data: &[u8]) {
        self.cleanup_counter += 1;
        if self.cleanup_counter > CLEANUP_INTERVAL {
            self.expire_connections(header_ts);
            self.cleanup_counter = 0;
        }

        let payload = &data[self.link_offset..];

        let Some(ip) = Ipv4Packet::new(payload) else {
            return;
        };
        if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return;
        }

        let ip_hdr_len = (ip.get_header_length() as usize) * 4;
        let Some(tcp) = TcpPacket::new(&payload[ip_hdr_len..]) else {
            return;
        };

        let flags = tcp.get_flags();
        let src_addr = ip.get_source();
        let dst_addr = ip.get_destination();
        let src_port = tcp.get_source();
        let dst_port = tcp.get_destination();

        if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
            // SYN-ACK: new connection, store biased toward initiator
            // (reverse src/dst since this is the server's response)
            let key = ConnectionKey {
                src_addr: dst_addr,
                src_port: dst_port,
                dst_addr: src_addr,
                dst_port: src_port,
            };
            let state = ConnectionState {
                seq: tcp.get_acknowledgement(),
                timestamp: header_ts,
            };
            self.connections.insert(key, state);
        } else if flags & TcpFlags::RST != 0
            || flags & (TcpFlags::FIN | TcpFlags::ACK) == (TcpFlags::FIN | TcpFlags::ACK)
        {
            // Connection teardown: check if it matches a tracked connection
            let key = ConnectionKey {
                src_addr,
                src_port,
                dst_addr,
                dst_port,
            };

            if let Some(stored) = self.connections.remove(&key) {
                self.check_scan(&key, tcp.get_sequence(), &stored);
            } else {
                // Try reversed direction (server sent teardown)
                let rev_key = ConnectionKey {
                    src_addr: dst_addr,
                    src_port: dst_port,
                    dst_addr: src_addr,
                    dst_port: src_port,
                };
                self.connections.remove(&rev_key);
            }
        }
    }

    fn check_scan(&self, key: &ConnectionKey, seq: u32, stored: &ConnectionState) {
        let seq_val = seq;
        let stored_seq = stored.seq;
        if seq_val >= stored_seq && seq_val <= stored_seq.wrapping_add(2) {
            let msg = format!(
                "TCP probe from {}:{} to {}:{}",
                key.src_addr, key.src_port, key.dst_addr, key.dst_port
            );
            if self.use_syslog {
                log::info!("Possible TCP port scan: {}", msg);
            } else {
                eprintln!("[{}] {}", Local::now().format("%b %d %H:%M:%S"), msg);
            }
        }
    }

    fn expire_connections(&mut self, now: Duration) {
        let expire_threshold = Duration::from_secs(EXPIRE_SECONDS);
        self.connections
            .retain(|_, state| now.saturating_sub(state.timestamp) < expire_threshold);
    }
}

fn get_link_offset(datalink: pcap::Linktype) -> usize {
    match datalink {
        pcap::Linktype::ETHERNET => 14,
        pcap::Linktype(8) => 16,  // SLIP
        pcap::Linktype(9) => 4,   // PPP
        _ => 14,
    }
}

fn run_capture<T: pcap::Activated>(mut cap: Capture<T>, descry: &mut Descry) {
    while let Ok(packet) = cap.next_packet() {
        let ts = Duration::new(
            packet.header.ts.tv_sec as u64,
            (packet.header.ts.tv_usec as u32) * 1000,
        );
        descry.process_packet(ts, packet.data);
    }
}

fn main() {
    let args = Args::parse();

    eprintln!("Descry 1.0 [TCP port scan detection tool]");

    if args.syslog {
        syslog::init(
            syslog::Facility::LOG_DAEMON,
            log::LevelFilter::Info,
            Some("descry"),
        )
        .expect("Failed to initialize syslog");
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    if let Some(ref file) = args.file {
        let mut cap = Capture::from_file(file).expect("Failed to open capture file");
        let link_offset = get_link_offset(cap.get_datalink());
        cap.filter(BPF_FILTER, true).expect("Failed to set BPF filter");
        let mut descry = Descry::new(args.syslog, link_offset);
        run_capture(cap, &mut descry);
    } else {
        let device_name = args.interface.unwrap_or_else(|| {
            Device::lookup()
                .expect("Failed to lookup device")
                .expect("No device found")
                .name
        });

        let mut cap = Capture::from_device(device_name.as_str())
            .expect("Failed to open device")
            .promisc(args.all_hosts)
            .snaplen(1500)
            .timeout(0)
            .open()
            .expect("Failed to activate capture");

        let link_offset = get_link_offset(cap.get_datalink());
        cap.filter(BPF_FILTER, true).expect("Failed to set BPF filter");
        let mut descry = Descry::new(args.syslog, link_offset);
        run_capture(cap, &mut descry);
    };
}
