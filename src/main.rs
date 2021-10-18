extern crate clap;
extern crate pnet;
extern crate pnet_datalink;

use std::env;
use std::io::{self, Write};
use std::net::{AddrParseError, IpAddr, Ipv4Addr};
use std::process;

use clap::{App, Arg};

use pnet_datalink::{Channel, MacAddr, NetworkInterface};

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations};
use pnet::packet::arp::{ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::{MutablePacket, Packet};

use env_logger;
use log::{info, debug, Level};

fn get_mac_through_arp(interface: NetworkInterface, target_ip: Ipv4Addr) -> MacAddr {
    let source_ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .unwrap();

    let (mut sender, mut receiver) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac_address());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac_address());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    sender
        .send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();

    println!("Sent ARP request");

    let buf = receiver.next().unwrap();

    let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();

    println!("Received reply");

    arp.get_sender_hw_addr()
}

fn print_interfaces () {
    for interface in pnet_datalink::interfaces() {
        println!("{}", interface.name);
    }
}

fn main() {
    let matches = App::new("pktool")
    .version("1.0")
    .author("w.tknv <tknv@twitter>")
    .about("A pktool just send what you want(best effort)")
    .arg(Arg::with_name("interfaces")
            .short("L")
            .long("interfaces")
            .help("Prints own interfaces"),
    )
    .arg(Arg::with_name("verbose")
            .short("v")
            .multiple(true)
            .help("verbosity level"),
    )
    .arg(
        Arg::with_name("protocol")
            .help("set protocol by Hex. E.g. TCP; -p 0x06, ARP; -p 0x0806")
            .short("p")
            .long("protocol")
            .takes_value(true),
            // .required(true),
    )
    .arg(
        Arg::with_name("interface")
            .help("set an interface to use sending packets")
            .short("I")
            .long("interface")
            .takes_value(true),
            // .required(true),
    )
    .arg(
        Arg::with_name("destination")
            .help("A destination of packets. E.g. IP address or MAC address")
            .index(1),
    )
    .get_matches();

    // log
    let log_level = match matches.occurrences_of("verbose") {
        0 => "info",
        1 | _ => "debug",
    };
    env::set_var("RUST_LOG", log_level);
    env_logger::init();

    // protocol
    let pkt_protocol = matches.value_of("protocol").unwrap_or("Default protocol");
    debug!("set protocol: {}", pkt_protocol);

    // interface
    let pkt_interface = matches.value_of("interface").unwrap_or("Default lo");
    debug!("set interface: {}", pkt_interface);

    // interfaces
    if matches.is_present("interfaces") {
        println!("Please use an interface from below list");
        print_interfaces();
    }

    // let mut args = env::args().skip(1);
    // let iface_name = match args.next() {
    //     Some(n) => n,
    //     None => {
    //         writeln!(
    //             io::stderr(),
    //             "USAGE: arp_packet <NETWORK INTERFACE> <TARGET IP>"
    //         )
    //         .unwrap();
    //         process::exit(1);
    //     }
    // };

    // let target_ip: Result<Ipv4Addr, AddrParseError> = match args.next() {
    //     Some(n) => n.parse(),
    //     None => {
    //         writeln!(
    //             io::stderr(),
    //             "USAGE: arp_packet <NETWORK INTERFACE> <TARGET IP>"
    //         )
    //         .unwrap();
    //         process::exit(1);
    //     }
    // };

    // let interfaces = pnet_datalink::interfaces();
    // let interface = interfaces
    //     .into_iter()
    //     .find(|iface| iface.name == iface_name)
    //     .unwrap();
    // let _source_mac = interface.mac_address();

    // let target_mac = get_mac_through_arp(interface, target_ip.unwrap());

    // println!("Target MAC address: {}", target_mac);
}