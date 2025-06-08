use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use pcap::Capture;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};

#[derive(Default)]
struct Stats {
    ip: u64,
    ip_with_options: u64,
    tcp: u64,
    tcp_with_options: u64,
}

fn percent(numerator: u64, denominator: u64) -> f64 {
    match denominator {
        0 => 0.0,
        _ => (numerator as f64) / (denominator as f64) * 100.0,
    }
}

impl Stats {
    fn print_stats(&self) {
        let ip_percent = percent(self.ip_with_options, self.ip);
        let tcp_percent = percent(self.tcp_with_options, self.tcp);

        println!("--- Traffic Stats ---");
        println!("IP packets seen:             {}", self.ip);
        println!("IP packets with options:     {}", self.ip_with_options);
        println!("Percentage of IP packets:    {:.2}%", ip_percent);

        println!("TCP segments seen:           {}", self.tcp);
        println!("TCP segments with options:   {}", self.tcp_with_options);
        println!("Percentage of TCP packets:   {:.2}%", tcp_percent);

        println!("-------------------------------\n");
    }
}

fn main() {

    let stats = Arc::new(Mutex::new(Stats::default())); 
    let stats_clone = Arc::clone(&stats);

    //thread 1 stampa le statistiche ogni 5 secondi
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        let s = stats_clone.lock().unwrap();
        s.print_stats();
    });
    // cattura i pacchetti dell'interfaccia  en0
    let mut cap = Capture::from_device("en0")
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .open()
        .unwrap();
    
    //leggo i pacchetti uno alla volta e salvo i dati grezzi del pacchetto in packet_data per elaborarli
    while let Ok(packet) = cap.next_packet() {
        let packet_data = packet.data; //byte
        //interpreto i byte grezzi del pacchetto in strutture di header, blocco le statistiche per aggiornarle in modo sicuro in un ambiente multithread
        if let Ok(parsed) = PacketHeaders::from_ethernet_slice(packet_data) {
            let mut stats = stats.lock().unwrap(); //stats.lock().unwrap() blocca il Mutex, prendendo il permesso esclusivo per modificare i dati dentro Stats

            //contollo se ho un pacchetto IP
            match parsed.net {
                Some(ip_header) => {
                    stats.ip += 1;

                    // Controlla se IP header ha opzioni (solo IPv4 supporta opzioni)
                    match ip_header {
                        NetHeaders::Ipv4(header, _) => {
                            if header.ihl() > 5 {
                                stats.ip_with_options += 1;
                            }
                        }
                        _ => {}
                    }
                }
                None => {}
            }

            match parsed.transport {
                 Some(TransportHeader::Tcp(tcp_header)) => {
                    stats.tcp += 1;
                    //Se il campo delle opzioni TCP NON è vuoto” — cioè se ci sono opzioni TCP presenti — esegui il codice dentro le parentesi 
                    if !tcp_header.options.is_empty() {
                        stats.tcp_with_options += 1;
                     }
                 }
                      _ => {}
}

        }
    }
}
