#![feature(lookup_host)]
#[macro_use] extern crate log;
extern crate simplelog;
extern crate getopts;
extern crate eui48;
extern crate csv;
extern crate rand;

use simplelog::{WriteLogger,LevelFilter,Level,Config};
use getopts::Options;
use std::{env, thread};
use std::io::{Read};
use std::net::{UdpSocket,ToSocketAddrs};
use std::time::Duration;
use std::fs::{File,OpenOptions};
use eui48::MacAddress;
use rand::Rng;
use std::process::{Command, Stdio};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Insonnia: Wake up or shutdown machines.
Usage: 
     {program} shut CSVFILE [options]
     {program} wol CSVFILE [options]

Commands:
    shut    Shutdown windows machines, uses 'name' column for shutdown.exe
    wol     Wake up machines, uses 'hwaddress' column for wake-on-lan

Arguments:

    CSVFILE  path to csv file containing list machines.
             First column: MAC address
             Second column: a resolvable name,
             Third column: one of [ws,w,s]. 
                    ws: wake up and shutdown, 
                    w: only wake up, 
                    s: only shutdown.
             Other columns are ignored.

             Example csv:

             hwaddress,name,ops,notes
             80:c1:6e:ea:72:8e,My-Machine,ws,this colums is ignored
             50:c1:fb:25:12:83,Other_Machine,w,this colums is ignored \n", program=program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    // setup cli options
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("b", "bind", "local bind address. [Default: 0.0.0.0:0]", "IP:PORT");
    opts.optopt("p", "pause", "random pause from 0 to SECONDS. [Default: 10]", "SECONDS");
    opts.optopt("", "comment", "shutdown comment. [Default: 'insonnia automatic shutdown']", "TXT");
    opts.optopt("", "log", "path to log file.[Default: none]", "FILE");
    opts.optflag("n", "dry-run", "perform trial run without actually doing anything.");
    opts.optflag("f", "force", "ignore the column 'ops' and run the action, either wol or shut, on all machines.");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(_) => { 
            print_usage(&program, opts);
            return;
        }
    };
    if matches.free.is_empty() || matches.free.len() < 2 {
        print_usage(&program, opts);
        return;
    }
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    // setup logging
    if matches.opt_present("log") {
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(matches.opt_str("log").unwrap()).unwrap();
        let log_config = Config {time: Some(Level::Error), level: Some(Level::Error), target: Some(Level::Debug), location: Some(Level::Trace),time_format: Some("%F %T")};
        let _logger = WriteLogger::init(LevelFilter::Info, log_config, log_file);
    }


    // open CSV file
    let hwaddr_file:String = matches.free[1].clone();
    let reader = csv::ReaderBuilder::new()
        .comment(Some(b'#'))
        .flexible(true)
        .from_path(hwaddr_file)
        .expect("Can't open file");

    println!("Insonnia\n========");
    info!("Started insonnia");
    if matches.opt_present("dry-run") {
        println!("> running dry run.");
        warn!("running dry run");
    }

    match matches.free[0].as_str() {
        "wol" => {
            info!("running command \"wol\"");
            wakeup(&matches, reader)
        },
        "shut" => {
            info!("running command \"shut\"");
            shutdown(&matches, reader)
        },
        _ => {
            print_usage(&program, opts);
            return;
        }
    };

}

fn wakeup(matches:&getopts::Matches,mut reader: csv::Reader<File>) {
    let bind_address:String = match matches.opt_str("bind") {
        Some(v) => v,
        None => String::from("0.0.0.0:0")
    };

    let pause_range:u64 = match matches.opt_str("pause") {
        Some(v) => v.parse::<u64>().expect("can't read --pause value, must be an integer."),
        None => 10
    };

    // setup socket
    let socket = UdpSocket::bind(bind_address).expect("Could not bind to address");
    socket.set_broadcast(true).expect("Can't set socket to broadcast");
    
    for result in reader.records() {
        let record = result.expect("Error reading CSV data");
        if !matches.opt_present("force") && &record[2] != "ws" && &record[2] != "w" {
            // skip this record
            continue;
        }
        let hwaddr = record[0].to_string();
        let target_name = record[1].to_string();
        println!("Waking up {} ({})", hwaddr, target_name);
        info!("waking up {} ({})", hwaddr, target_name);
        // Parse MAC
        let mac:Vec<u8> = match MacAddress::parse_str(&hwaddr) {
            Ok(m) => { m.as_bytes().to_vec() },
            Err(e) => {
                println!("  Invalid MAC ADDRESS \"{}\": {} ", hwaddr, e);
                error!("  Invalid MAC ADDRESS \"{}\": {} ", hwaddr, e);
                continue;
            }
        };
        // Create magic packet
        let mut packet:Vec<u8> = wol_packet(&mac);

        if matches.opt_present("dry-run") {
            // Break magic packet so no machine will get awaken
            packet.truncate(50);
        }
        // Send packet
        for i in 0..2 { // send magic packet twice because some thimes one gets lost :-P
            match socket.send_to(&packet, "255.255.255.255:9") {
                Ok(_) => {
                    println!(" Magic packet {} sent.", i);
                    info!("magic packet {} sent.", i);
                },
                Err(e) => {
                    println!(" Can't send magic packet to {}: {}", hwaddr, e);
                    error!("can't send magic packet to {}: {}", hwaddr, e);
                    continue;
                }
            };
            thread::sleep(Duration::from_secs(2));
        }

        // Pause
        let pause_for = match pause_range {
            0 => 0,
            _ => rand::thread_rng().gen_range(0,pause_range)
        };
        if matches.opt_present("dry-run") { // don't pause when dry-run
            println!(" Pause for {} seconds. -- skip because of dry-run", pause_for);
            continue;
        } else {
            println!(" Pause for {} seconds", pause_for);
            info!(" Pause for {} seconds", pause_for);
            thread::sleep(Duration::from_secs(pause_for));
        }
    }
}

fn shutdown(matches:&getopts::Matches,mut reader: csv::Reader<File>) {
    let shutdown_comment = match matches.opt_str("comment") {
        Some(v) => format!("/c {}", v),
        None    => format!("/c {}", "insonnia automatic shutdown")
    };

    for result in reader.records() {
        let record = result.expect("Error reading CSV data");
        if !matches.opt_present("force") && &record[2] != "ws" && &record[2] != "s" {
            // skip this record
            continue;
        }
        let hwaddr = record[0].to_string();
        let target_name = record[1].to_string();
        println!("Shutting down {} ({})", target_name, hwaddr);
        info!("Shutting down {} ({})", target_name, hwaddr);

        let mut command = Command::new("shutdown.exe");
        command.arg("/s")
            .args(&["/m", target_name.as_str()])
            .args(&["/t", "10"])
            .args(&["/c", shutdown_comment.as_str()])
            .args(&["/d", "p:4:1"])
            .stderr(Stdio::piped());

        if matches.opt_present("dry-run") { // don't run when dry-run
            let ip = match lookup(&target_name) {
                Ok(o) => { o }
                Err(e) => {
                    println!(" Impossible to resolve {}: {}", target_name, e);
                    error!(" Impossible to resolve {}: {}", target_name, e);
                    continue;
                }
            };
            println!(" Resolved {} to {}", target_name, ip[0]);
            info!(" Resolved {} to {}", target_name, ip[0]);
            println!(" Shutdown command issued. -- skip because of dry-run");
            info!(" Shutdown command issued. -- skip because of dry-run");
            continue;
        }
        let mut child = match command.spawn() {
            Ok(c) => {c},
            Err(e) => {
                println!(" Shutdown command failed to start: {}", e);
                error!(" Shutdown command failed to start: {}", e);
                continue;
            }
        };
        let exit_status = match child.try_wait() {
            Ok(Some(status)) => {status}
            Ok(None) => { 
                match child.wait() {
                    Ok(status) => {status},
                    Err(e) => {
                        println!(" Something went wrong: {}", e);
                        error!(" Something went wrong: {}", e);
                        continue;
                    }
                }
            }
            Err(e) => {
                println!(" Something went wrong: {}", e);
                error!(" Something went wrong: {}", e);
                continue;
            }
        };
        match exit_status.code().expect("Can't start shutdown.exe") {
            0 => {
                println!(" Shutdown command issued");
                info!(" Shutdown command issued");
            },
            _ => {
                let mut stderr:String = String::from("unknow");
                match child.stderr {
                    None => {},
                    Some(mut s) => {
                        s.read_to_string(&mut stderr).ok();
                        ();
                    },
                };
                println!(" Shutdown command exited with error {}: {}", exit_status, stderr);
                error!(" Shutdown command exited with error {}: {}", exit_status, stderr);
            }
        };
    };
}

fn lookup(name: &String) -> Result<Vec<std::net::IpAddr>, std::io::Error> {
    let results:Vec<std::net::SocketAddr> = name.to_socket_addrs()?.collect::<Vec<std::net::SocketAddr>>();
    let mut ips:Vec<std::net::IpAddr> = Vec::new();
    for ip in results {
        ips.push(ip.ip());
    };
        
    Ok(ips)
}

fn wol_packet(mac:&Vec<u8>) -> Vec<u8> {
    let mut packet = vec![0u8; 102];

    // The header is 6 0xFFs
    for i in 0..6 {
    packet[i] = 0xFF;
    }

    // We copy the mac address 16 times.
    for i in 0..16 {
        for j in 0..6 {
            packet[6 + (i * 6) + j] = mac[j];
        }
    }
    return packet
} 
