use std::path::PathBuf;
use libp2p::core::Multiaddr;
use libp2p::wasm_ext;

pub struct TransportConfig {
    pub mdns: bool,
    pub wasm_ext_transport: Option<wasm_ext::ExtTransport>,
    pub yamux: bool,
}

pub struct NetworkConfiguration {
    pub config_path: Option<PathBuf>,
    pub listen_addresses: Vec<Multiaddr>,
    pub max_in_peers: u32,
    pub max_out_peers: u32,
    pub max_peers: u32,
    pub version: String,
    pub name: String,
    pub transport: TransportConfig,
}
