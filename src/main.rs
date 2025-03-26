extern crate alloc;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use ingot::{
    Ingot,
    ethernet::{Ethernet, Ethertype},
    geneve::{Geneve, GeneveOpt, GeneveOptionType, Vni},
    ip::{IpProtocol, Ipv4, Ipv6},
    types::{Emit, HeaderLen, Ipv4Addr, Ipv6Addr, primitives::*},
    udp::Udp,
};
use internet_checksum::Checksum;
use std::{
    fs::File,
    io::{BufReader, Read, Write},
};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
    byteorder::{BE, U32},
};

/// Encapsulate
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(value_enum)]
    /// Type of encapsulation to apply to the output packet.
    encap: EncapType,

    #[arg(value_enum, short, long, default_value = "v4")]
    /// Type of IP to use in output encapsulation.
    ip: IpType,

    #[arg(short, long, default_value = "0")]
    /// VNI to wrap packets within.
    opts_len: usize,

    /// Path to an input `.snoop` file.
    input: String,

    /// Path to write the modified `.snoop` file into.
    out: String,

    /// Writes to the destination file even if it exists.
    #[arg(short, long)]
    force_write: bool,

    /// Skips the outer UDP checksum.
    #[arg(short, long)]
    skip_udp_csum: bool,
}

impl Args {
    fn validate(&self) -> anyhow::Result<()> {
        if self.encap == EncapType::Vxlan && self.opts_len != 0 {
            anyhow::bail!("VXLAN does not support options");
        } else if self.opts_len % 4 != 0 {
            anyhow::bail!("Geneve options must be a multiple of 4B long");
        }
        Ok(())
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum EncapType {
    Geneve,
    Vxlan,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum IpType {
    V4,
    V6,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct Vxlan {
    #[ingot(default = 0)]
    rsvd_0: u4,
    #[ingot(default = 1)]
    pub valid_vni: u1,
    #[ingot(default = 0)]
    rsvd_1: u27be,
    #[ingot(is = "[u8; 3]")]
    pub vni: Vni,
    #[ingot(default = 0)]
    rsvd_2: u8,
}

const SNOOP_MAGIC: &[u8; 8] = b"snoop\0\0\0";
const SNOOP_VERSION: u32 = 2;
const SNOOP_ETHERNET: u32 = 4;

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct SnoopHeader {
    magic: [u8; 8],
    version: U32<BE>,
    mac_type: U32<BE>,
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
#[allow(unused)]
struct PacketPreamble {
    original_len: U32<BE>,
    msg_len: U32<BE>,
    tot_len: U32<BE>,
    drops: U32<BE>,
    ts_secs: U32<BE>,
    ts_ns: U32<BE>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    args.validate()?;

    let in_file = File::open(&args.input).context("failed to open input snoop file")?;
    let mut in_file = BufReader::new(in_file);

    let mut out_file = if args.force_write {
        File::create(&args.out).context("opening file for writing")
    } else {
        File::create_new(&args.out).context("opening new file for writing")
    }?;

    let mut hdr_buf = vec![0; size_of::<SnoopHeader>()];
    in_file
        .read_exact(&mut hdr_buf[..])
        .context("insufficient bytes for snoop header")?;
    let hdr = SnoopHeader::ref_from_bytes(&hdr_buf[..]).expect("sizeof guarantee");

    if hdr.magic != *SNOOP_MAGIC {
        anyhow::bail!(
            "incorrect magic bytes: saw {:?}, wanted {SNOOP_MAGIC:?}",
            hdr.magic
        );
    }
    if hdr.version != SNOOP_VERSION {
        anyhow::bail!(
            "incorrect version: saw {}, wanted {SNOOP_VERSION}",
            hdr.version
        );
    }
    if hdr.mac_type != SNOOP_ETHERNET {
        anyhow::bail!(
            "incorrect mac_type: saw {}, wanted {SNOOP_ETHERNET}",
            hdr.mac_type
        );
    }

    out_file.write_all(&hdr_buf)?;

    let mut preamble_buf = vec![0; size_of::<PacketPreamble>()];
    let mut pkt_buf = vec![0; 64 * 1024 * 1024];
    let mut i = 0;
    loop {
        if in_file.read_exact(&mut preamble_buf[..]).is_err() {
            break;
        }
        let preamble = PacketPreamble::ref_from_bytes(&preamble_buf[..]).expect("sizeof guarantee");
        if preamble.original_len != preamble.msg_len {
            eprintln!("truncated packet, skipping");
            continue;
        }

        if preamble.msg_len > 1024 * 1024 * 32 {
            anyhow::bail!("packet larger than 32 MiB (???)");
        }

        pkt_buf.resize(preamble.msg_len.get() as usize, 0);

        in_file
            .read_exact(&mut pkt_buf[..])
            .context("could not read out entire packet")?;

        // skip any pad bytes.
        let pad_len = preamble.tot_len.get() as usize - pkt_buf.len() - preamble_buf.len();
        std::io::copy(
            &mut in_file.by_ref().take(pad_len as u64),
            &mut std::io::sink(),
        )
        .context("skipping pad bytes")?;

        let out_pkt = encapsulate(&args, &pkt_buf, i);
        let mut out_preamble = *preamble;
        out_preamble.original_len = (out_pkt.len() as u32).into();
        out_preamble.msg_len = out_preamble.original_len;
        out_preamble.tot_len = out_preamble.msg_len + preamble_buf.len() as u32;

        out_file.write_all(out_preamble.as_bytes())?;
        out_file.write_all(&out_pkt)?;

        i += 1;
    }

    Ok(())
}

fn encapsulate(args: &Args, pkt: &[u8], i: u16) -> Vec<u8> {
    let vni = Vni::new(7777u32).unwrap();
    let (encap, destination) = match args.encap {
        EncapType::Geneve => {
            let opt_len = (args.opts_len << 2) as u8;
            let options = if opt_len == 0 {
                vec![]
            } else {
                let length = opt_len - 1;
                let data = vec![0xaa; (length as usize) >> 2];
                vec![GeneveOpt {
                    class: 0xFF00,
                    option_type: GeneveOptionType(0xff),
                    length,
                    data,
                    ..Default::default()
                }]
            };
            let g = Geneve {
                vni,
                opt_len,
                options: options.into(),
                ..Default::default()
            };

            (g.emit_vec(), 6081)
        }
        EncapType::Vxlan => {
            let v = Vxlan {
                vni,
                ..Default::default()
            };
            (v.emit_vec(), 4789)
        }
    };

    let mut udp = Udp {
        source: 0xff10,
        destination,
        length: (Udp::MINIMUM_LENGTH + encap.len() + pkt.len()) as u16,
        checksum: 0,
    };

    let (ip, mut pseudoheader, ethertype) = match args.ip {
        IpType::V4 => {
            let mut v4b = [0u8; Ipv4::MINIMUM_LENGTH];
            let mut v4 = Ipv4 {
                total_len: udp.length + Ipv4::MINIMUM_LENGTH as u16,
                identification: 0xabcd_u16.wrapping_add(i),
                protocol: IpProtocol::UDP,
                checksum: 0,
                source: Ipv4Addr::from_octets([192, 168, 2, 4]),
                destination: Ipv4Addr::from_octets([192, 168, 2, 4]),
                ..Default::default()
            };
            v4.emit_raw(&mut v4b[..]);

            let cksum = internet_checksum::checksum(&v4b);
            v4.checksum = u16::from_be_bytes(cksum);

            let mut pseudo = Checksum::new();
            pseudo.add_bytes(v4.source.as_bytes());
            pseudo.add_bytes(v4.destination.as_bytes());

            (v4.emit_vec(), pseudo, Ethertype::IPV4)
        }
        IpType::V6 => {
            let v6 = Ipv6 {
                payload_len: udp.length,
                next_header: IpProtocol::UDP,
                source: Ipv6Addr::from_segments([0xfd12, 0, 0, 0, 0, 0, 0, 0x0001]),
                destination: Ipv6Addr::from_segments([0xfd12, 0, 0, 0, 0, 0, 0, 0x0002]),
                ..Default::default()
            };

            let mut pseudo = Checksum::new();
            pseudo.add_bytes(v6.source.as_bytes());
            pseudo.add_bytes(v6.destination.as_bytes());

            (v6.emit_vec(), pseudo, Ethertype::IPV6)
        }
    };

    let eth = Ethernet {
        destination: "aa:aa:aa:aa:aa:aa".parse().unwrap(),
        source: "cc:cc:cc:cc:cc:cc".parse().unwrap(),
        ethertype,
    };

    if !args.skip_udp_csum {
        let mut udp_buf = [0u8; 8];
        udp.emit_raw(&mut udp_buf[..]);

        // catching up on pseudoheader
        pseudoheader.add_bytes(&[0, IpProtocol::UDP.0]);
        pseudoheader.add_bytes(udp.length.to_be().as_bytes());

        // payload
        pseudoheader.add_bytes(&udp_buf);
        pseudoheader.add_bytes(&encap);
        pseudoheader.add_bytes(pkt);
        udp.checksum = u16::from_be_bytes(pseudoheader.checksum());
    }

    (&eth, &ip, &udp, &encap, &pkt).emit_vec()
}
