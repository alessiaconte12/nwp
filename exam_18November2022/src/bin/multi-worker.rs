use std::sync::{Arc, Mutex};
use std::{thread, time::Duration};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::datalink::{Config, FanoutOption, FanoutType, NetworkInterface};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;


#[derive(Default, Debug)]
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

// funzione per sommare i dati di più stats
fn aggregate(stats_list: &[Arc<Mutex<Stats>>]) -> Stats {
    let mut total = Stats::default();
    for stats in stats_list {
        let stats = stats.lock().unwrap();
        total.ip += stats.ip;
        total.ip_with_options += stats.ip_with_options;
        total.tcp += stats.tcp;
        total.tcp_with_options += stats.tcp_with_options;
    }
    total
}

fn set_interface(iface: &str) -> Option<NetworkInterface> {
    datalink::interfaces().into_iter().find(|i| i.name == iface)
}

fn main() {
    // Prendo il nome dell’interfaccia da riga di comando en0
    let ifaces: Vec<_> = std::env::args().skip(1).collect();
    let iface = &ifaces[0];

    let num_threads = 4;
    let mut threads = vec![];

    // Creo vettore di stats condivise senza usare map
    let mut stats_vec: Vec<Arc<Mutex<Stats>>> = Vec::new();
    for _ in 0..num_threads {
        stats_vec.push(Arc::new(Mutex::new(Stats::default())));
    }

    for i in 0..num_threads {
        let iface = iface.clone(); // Per ogni thread creo una nuova copia del nome interfaccia, x evitare problemi di ownership
        let stats = Arc::clone(&stats_vec[i]); // Ogni thread ha un proprio record di statistiche

        threads.push(thread::spawn(move || {
            let interface = match set_interface(&iface) { // cerco l'interfaccia giusta, ossia en0
                Some(interface) => interface,
                None => panic!("Device {} not found", iface),
            };

            // creo la configurazione per il fanout
            let mut configuration = Config::default();
            let f_out: FanoutOption = FanoutOption { // Imposto il fanout, che serve a distribuire i pacchetti tra i thread senza duplicarli
                group_id: 1234,
                fanout_type: FanoutType::HASH,
                defrag: true, // permette di ricostruire i pacchetti IP frammentati
                rollover: false, // evita duplicazione
            };

            // attivo il fanout Linux sul socket di cattura dei pacchetti
            configuration.linux_fanout = Some(f_out);

            // creo il canale di cattura dei pacchetti
            let (_tx, mut rx) = match datalink::channel(&interface, configuration) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("Unsupported channel"),
                Err(e) => panic!("{}", e),
            };

            loop {
                match rx.next() {
                    Ok(frame) => {
                        if let Some(eth_pkt) = EthernetPacket::new(frame) {
                            if eth_pkt.get_ethertype() == EtherTypes::Ipv4 {
                                if let Some(ip_pkt) = Ipv4Packet::new(eth_pkt.payload()) {
                                    let mut stats = stats.lock().unwrap();
                                    stats.ip += 1;

                                    // Controlla se IP header ha opzioni (IHL > 5)
                                    if ip_pkt.get_header_length() > 5 {
                                        stats.ip_with_options += 1;
                                    }

                                    if ip_pkt.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                        if let Some(tcp_pkt) = TcpPacket::new(ip_pkt.payload()) {
                                            stats.tcp += 1;

                                            // TCP options sono in tcp_pkt.get_options()
                                            if !tcp_pkt.get_options().is_empty() {
                                                stats.tcp_with_options += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Ignora errori di lettura pacchetto o fai break se vuoi terminare
                    }
                }
            }
        }));
    }

    // Thread per stampare le statistiche ogni 5 secondi
    let stats_for_print = stats_vec.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(5));

            

            for (i, stats_mutex) in stats_for_print.iter().enumerate() {
                let stats = stats_mutex.lock().unwrap();
                println!("Thread {}:", i);
                stats.print_stats();
            }
                
            println!("Aggregated stats:");
            let aggregated = aggregate(&stats_for_print);
            aggregated.print_stats();
        }
    });

    // Attendo la terminazione dei thread di cattura
    for t in threads {
        let _ = t.join();
    }
}
