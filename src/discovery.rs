use crate::config::ProtocolName;
use bevy::utils::{HashMap, HashSet};
use libp2p::core::connection::{ConnectionId, ListenerId};
use libp2p::core::{ConnectedPoint, Multiaddr, PublicKey};
use libp2p::kad::handler::KademliaHandler;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{Kademlia, KademliaBucketInserts, KademliaConfig, QueryId, KademliaEvent, QueryResult as KadQueryResult, GetClosestPeersError};
use libp2p::mdns::Mdns;
use libp2p::swarm::protocols_handler::multi::MultiHandler;
use libp2p::swarm::toggle::Toggle;
use libp2p::swarm::{
    IntoProtocolsHandler, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
    ProtocolsHandler,
};
use libp2p::PeerId;
use std::error::Error;
use std::task::{Context, Poll};
use bevy::core::Timer;
use bevy::ecs::bevy_utils::Instant;
use libp2p::kad::record::Key;
use std::time::Duration;
use bevy::utils::tracing::field::debug;

// There are other options such as non-global addresses being inserting into the
// DHT, and if private ipv4 addresses are reported.
pub struct DiscoveryBuilder {
    local_peer_id: PeerId,
    user_defined_peers: Vec<(PeerId, Multiaddr)>,
    kademlias: HashMap<ProtocolName, Kademlia<MemoryStore>>,
    mdns: bool,
    discovery_limit: u64,
}

/// Discovery implementation that discovers nodes on the network.
pub struct Discovery {
    /// List of nodes that are user defined and their addresses.
    user_defined_peers: Vec<(PeerId, Multiaddr)>,
    /// Kademlia requests and answers.
    kademlias: HashMap<ProtocolName, Kademlia<MemoryStore>>,
    /// Toggle discovery on the local network.
    mdns: Toggle<Mdns>,
    last_kademlia_query: Instant,
    next_kademlia_query: Timer,
    local_peer_id: PeerId,
    discovery_limit: u64,
    allow_private_ipv4: bool,
    known_addresses: HashSet<Multiaddr>,
    connected: u32,
}

impl DiscoveryBuilder {
    pub fn new(local_public_key: PublicKey) -> Self {
        DiscoveryBuilder {
            local_peer_id: local_public_key.into_peer_id(),
            user_defined_peers: Vec::new(),
            kademlias: HashMap::default(),
            mdns: false,
            discovery_limit: std::u64::MAX,
        }
    }

    pub fn discovery_limit(mut self, limit: u64) -> Self {
        self.discovery_limit = limit;
        self
    }

    pub fn user_defined_peers(mut self, peers: I) -> Self
    where
        I: IntoIterator<Item = (PeerId, Multiaddr)>,
    {
        for (peer_id, addr) in peers.into_iter() {
            self.user_defined_peers.push((peer_id, addr));
        }
        self
    }

    pub fn mdns(mut self, b: bool) -> Self {
        self.mdns = b;
        self
    }

    pub fn add_kademlia(mut self, name: ProtocolName) -> Self {
        let kademlia_name = name.into_kademlia_protocol();
        if self.kademlias.contains_key(&name) {
            warn!(target: "bevy_p2p", "Kademlia already registered {:?}", name);
        }

        let mut config = KademliaConfig::default();
        config.set_protocol_name(kademlia_name);
        // TODO: check if we should do this manually or automatically.
        config.set_kbucket_inserts(KademliaBucketInserts::Manual);

        let store = MemoryStore::new(self.local_peer_id.clone());
        let kad = Kademlia::with_config(self.local_peer_id.clone(), store, config);

        self.kademlias.insert(name, kad);

        self
    }

    pub fn allow_private_ipv4(mut self, b: bool) -> Self {
        self.allow_private_ipv4 = b;
        self
    }

    pub fn build(mut self) -> Discovery {
        for (peer_id, addr) in &self.user_defined_peers {
            for kademlia in self.kademlias.values_mut() {
                kademlia.add_address(peer_id, addr.clone());
            }
        }

        Discovery {
            user_defined_peers: self.user_defined,
            kademlias: self.kademlias,
            mdns: if self.mdns {
                match Mdna::new() {
                    Ok(mdns) => Some(mdns).into(),
                    Err(err) => {
                        warn!(target: "bevy_p2p", "mDNS failed to initialize: {:?}", err);
                        None.into()
                    }
                }
            } else {
                None.into()
            },
            last_kademlia_query: Instant::now(),
            next_kademlia_query: Default::default(),
            local_peer_id: self.local_peer_id,
            discovery_limit: self.discovery_limit,
            allow_private_ipv4: self.allow_private_ipv4,
            known_addresses: HashSet::default(),
            connected: 0,
        }
    }
}

impl Discovery {
    pub fn builder(local_public_key: PublicKey) -> DiscoveryBuilder {
        DiscoveryBuilder::new(local_public_key)
    }

    pub fn known_peers(&mut self) -> HashSet<PeerId> {
        let mut peers = HashSet::default();
        for kademlia in self.kademlias.values_mut() {
            for bucket in kademlia.kbuckets() {
                for entry in bucket.iter() {
                    peers.insert(entry.node.key.preimage().clone());
                }
            }
        }
        peers
    }
    // pub fn known_peers(&mut self)
}

pub enum DiscoveryEvent {
    Discovery {
        peer_id: PeerId,
    },

    UnroutableDiscovery {
        peer_id: PeerId,
    },
    
    RandomKademliaWalkStarted {
        protocols: Vec<ProtocolName>,
    },

    RecordFound {
        key_values: Vec<(Key, Vec<u8>)>,
        duration: Duration,
    },

    RecordNotFound {
        key: Key,
        duration: Duration,
    },

    PutRecord {
        key: Key,
        duration: Duration,
    },

    PutRecordFailed {
        key: Key,
        duration: Duration,
    }
}

impl NetworkBehaviour for Discovery {
    type ProtocolsHandler = Multihandler<ProtocolName, KademliaHandler<QueryId>>;
    type OutEvent = DiscoveryEvent;

    fn new_handler(&mut self) -> Self::ProtocolsHandler {
        let iter = self.kademlias.iter_mut().map(|(protocol_name, kademlia)| {
            (
                protocol_name.clone(),
                kademlia.new_handler(),
            )
        });

        MultiHandler::try_from_iter(iter)
            .expect("There can be at most one handle per `ProtocolName`.")
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        let mut peers: Vec<Multiaddr> = self
            .user_defined_peers
            .iter()
            .filter_map(|(p_id, addr)| {
                if p_id == peer_id {
                    Some(addr.clone())
                } else {
                    None
                }
            })
            .collect();

        let mut kademlia_peers = {
            let mut peers = Vec::new();
            for kademlia in self.kademlias.values_mut() {
                peers.extend(kademlia.addresses_of_peer(peer_id))
            }
            peers.extend(self.mdns.addresses_of_peer(peer_id));

            if !self.allow_private_ipv4 {
                peers.retain(|addr| {
                    if let Some(Protocol::Ip4(addr)) = addr.iter().next() {
                        if addr.is_private() {
                            return false;
                        }
                    }
                    true
                })
            }
            kademlia.extend(peers)
        };

        peers.extend(kademlia_peers);

        peers
    }

    fn inject_connected(&mut self, peer_id: &PeerId) {
        for kademlia in self.kademlias.values_mut() {
            kademlia.inject_connected(peer_id);
        }
    }

    fn inject_disconnected(&mut self, peer_id: &PeerId) {
        for kademlia in self.kademlias.values_mut() {
            kademlia.inject_disconnected(peer_id);
        }
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        conn_id: &ConnectionId,
        conn_point: &ConnectedPoint,
    ) {
        self.connected += 1;
        for kademlia in self.kademlias.values_mut() {
            kademlia.inject_connection_established(peer_id, conn_id, conn_point);
        }
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        conn_id: &ConnectionId,
        conn_point: &ConnectedPoint,
    ) {
        self.connected -= 1;
        for kademlia in self.kademlias.values_mut() {
            kademlia.inject_connection_closed(peer_id, conn_id, conn_point);
        }
    }

    fn inject_address_change(
        &mut self,
        peer_id: &PeerId,
        conn_id: &ConnectionId,
        old_conn_point: &ConnectedPoint,
        new_conn_point: &ConnectedPoint,
    ) {
        for kademlia in self.kademlias.values_mut() {
            kademlia.inject_address_change(peer_id, conn_id, old_conn_point, new_conn_point);
        }
    }

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        connection: ConnectionId,
        (pid, event): <Self::ProtocolsHandler as ProtocolsHandler>::OutEvent,
    ) {
        if let Some(kademlia) = self.kademlias.get_mut(&pid) {
            return kademlia.inject_event(peer_id, connection, event);
        }
    }

    fn inject_addr_reach_failure(
        &mut self,
        peer_id: Option<&PeerId>,
        addr: &Multiaddr,
        error: &dyn Error,
    ) {
        for kademlia in self.kademlias.values_mut() {
            kademlia.inject_addr_reach_failure(peer_id, addr, error);
        }
    }

    fn inject_dial_failure(&mut self, peer_id: &PeerId) {
        for kademlia in self.kademlias.values_mut() {
            kademlia.inject_dial_failure(peer_id);
        }
    }

    fn inject_new_listen_addr(&mut self, addr: &Multiaddr) {
        for kademlia in self.kademlias.values_mut() {
            kademlia.inject_new_listen_addr(addr);
        }
    }

    fn inject_expired_listen_addr(&mut self, addr: &Multiaddr) {
        for kademlia in self.kademlias.values_mut() {
            kademlia.inject_expired_listen_addr(addr);
        }
    }

    fn inject_new_external_addr(&mut self, addr: &Multiaddr) {
        for kademlia in self.kademlias.values_mut() {
            kademlia.inject_new_external_addr(addr);
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        params: &mut impl PollParameters,
    ) -> Poll<
        NetworkBehaviourAction<
            <Self::ProtocolsHandler as ProtocolsHandler>::InEvent,
            Self::OutEvent,
        >,
    > {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(ev));
        }

        let elapsed = self.last_kademlia_query.elapsed().as_secs_f32();
        self.next_kademlia_query.tick(elapsed);
        if self.next_kademlia_query.finished() {
            let started = if self.connections < self.discovery_limit {
                let peer_id = PeerId::random();
                for kademlia in self.kademlias.values_mut() {
                    kademlia.get_closest_peers(peer_id.clone());
                }

                true
            } else {
                false
            };

            self.last_kademlia_query = Instant::now();

            if started {
                let event = DiscoveryOut::RandomKademliaWalkStarted(self.kademlias.keys().cloned().collect());
                return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event));
            }
        }
        
        for (protocol_name, kademlia) in &mut self.kademlias {
            while let Poll::Ready(event) = kademlia.poll(cx, params) {
                use KademliaEvent::*;
                
                match event {
                    NetworkBehaviourAction::GenerateEvent(event) => match event {
                        RoutingUpdated { peer, .. } | RoutablePeer { peer, .. } => {
                            let event = DiscoveryEvent::Discovery {
                                peer_id: peer,
                            };
                            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event));
                        }
                        UnroutablePeer { peer, .. } => {
                            let event = DiscoveryEvent::UnroutableDiscovery {
                                peer_id: peer,
                            };
                            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event));
                        }
                        PendingRoutablePeer { .. } => {}
                        QueryResult { result: KadQueryResult::GetClosestPeers(res), .. } => {
                            match res {
                               Ok(g) => {
                                   if g.peers.is_empty() && self.connected != 0 {
                                      debug!(target: "bevy_p2p", "Random Kademlia query has yielded empty results.");
                                   }
                               },
                                Err(GetClosestPeersError::Timeout { key, peers }) => {
                                   debug!(target: "bevy_p2p", "Query for {:?} timed out with {} results."); 
                                }
                            }
                        }
                        QueryResult { result: KadQueryResult::GetRecord(res), stats, .. } => {
                            let event = match res {
                                Ok(g) => {
                                    let results = g.records.into_iter().map(|r| (r.record.key, r.record.value)).collect();
                                    DiscoveryEvent::RecordFound { key_values: results, duration: stats.duration().unwrap_or_else(Default::default) }
                                }
                                Err(e) => {
                                    warn!(target: "bevy_p2p", "Failed to get record: {:?}", e);
                                    DiscoveryEvent::RecordNotFound {
                                        key: e.into_key(),
                                        duration,
                                    }
                                }
                            };
                            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event));
                        }
                        QueryResult { result: KadQueryResult::PutRecord(res), stats, .. } => {
                            let event = match res {
                                Ok(v) => DiscoveryEvent::ValuePut(v.key, stats.duration().unwrap_or_else(Default::default)),
                                Err(e) => {
                                    warn!(target: "bevy_p2p", "Failed to put record: {:?}", e);
                                    DiscoveryEvent::PutRecordFailed {
                                        key: e.into_key(),
                                        duration: stats.duration().unwrap_or_else(Default::default),
                                    }
                                }
                            };
                            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(event));
                        }
                        QueryResult { result: KadQueryResult::RepublishRecord(res), .. } => {
                            match res {
                                Ok(v) => debug!(target: "bevy_p2p", "Record published: {:?}", v.key),
                                Err(e) => warn!(target: "bevy_p2p", "Republishing of record {:?} failed with: {:?}", e.key(), e)
                            }
                        }
                        QueryResult { result: KadQueryResult::Bootstrap(res), .. } => {
                            match res {
                                Ok(v) => debug!(target: "bevy_p2p", "Bootstrapping peer {} with {} remaining", v.peer, v.num_remaining),
                                Err(e) => warn!(target: "bevy_p2p", "Bootstrapping timed out with peer: {:?}"),
                            }
                        }
                        e => {
                            warn!(target: "bevy_p2p", "Unhandled Kademlia event: {:?}", e);
                        }
                    }
                    NetworkBehaviourAction::DialAddress { address } =>
                        return Poll::Ready(NetworkBehaviourAction::DialAddress { address }),
                    NetworkBehaviourAction::DialPeer { peer_id, condition } =>
                        return Poll::Ready(NetworkBehaviourAction::DialPeer { peer_id, condition }),
                    NetworkBehaviourAction::NotifyHandler { peer_id, handler, event } =>
                        return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                            peer_id,
                            handler,
                            event: (pid.clone(), event)
                        }),
                    NetworkBehaviourAction::ReportObservedAddr { address, score } =>
                        return Poll::Ready(NetworkBehaviourAction::ReportObservedAddr { address, score }),
                }
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {

}