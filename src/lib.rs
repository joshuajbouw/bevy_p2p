pub fn it_works() -> bool {
    true

#[derive(Clone)]
pub struct NetworkStatus {
    pub connected_peers: usize,
    pub active_peers: usize,
    pub total_bytes_inbound: u64,
    pub total_bytes_outbound: u64,
}
