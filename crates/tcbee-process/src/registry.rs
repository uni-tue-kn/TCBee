//! Flow identities shared by the workers.
//!
//! Flow ids start at 1 and follow discovery order, which depends on the thread schedule; nothing
//! relies on the numbering (tests compare flows by tuple).

use std::collections::HashMap;
use std::sync::Mutex;

use ts_storage::{Flow, IpTuple};

/// All flows seen so far. New flows are rare, so one mutex is enough; workers keep a
/// [`FlowCache`] in front of it.
#[derive(Default)]
pub struct FlowRegistry {
    flows: Mutex<HashMap<IpTuple, i64>>,
}

impl FlowRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn id_of(&self, tuple: IpTuple) -> i64 {
        // A poisoned lock means a worker panicked while holding it; the map is still consistent
        // (insert is the only mutation), and the pipeline reports the panic anyway.
        let mut flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        let next = flows.len() as i64 + 1;
        *flows.entry(tuple).or_insert(next)
    }

    /// Worker-local view that only locks for flows it has not seen.
    pub fn cache(&self) -> FlowCache<'_> {
        FlowCache {
            registry: self,
            local: HashMap::new(),
        }
    }

    /// The flows ordered by id.
    pub fn into_flows(self) -> Vec<Flow> {
        let map = self.flows.into_inner().unwrap_or_else(|e| e.into_inner());
        let mut flows: Vec<Flow> = map.into_iter().map(|(t, id)| Flow::new(id, t)).collect();
        flows.sort_by_key(|f| f.id);
        flows
    }
}

pub struct FlowCache<'a> {
    registry: &'a FlowRegistry,
    local: HashMap<IpTuple, i64>,
}

impl FlowCache<'_> {
    pub fn id(&mut self, tuple: IpTuple) -> i64 {
        if let Some(&id) = self.local.get(&tuple) {
            return id;
        }
        let id = self.registry.id_of(tuple.clone());
        self.local.insert(tuple, id);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(sport: i64) -> IpTuple {
        IpTuple {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            sport,
            dport: 80,
            l4proto: 6,
        }
    }

    #[test]
    fn ids_are_stable_across_caches_and_threads() {
        let reg = FlowRegistry::new();
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    let mut c = reg.cache();
                    for p in 0..100 {
                        let a = c.id(tuple(p));
                        assert_eq!(a, c.id(tuple(p)));
                    }
                });
            }
        });
        let mut c = reg.cache();
        let ids: Vec<i64> = (0..100).map(|p| c.id(tuple(p))).collect();
        let flows = reg.into_flows();
        assert_eq!(flows.len(), 100);
        assert_eq!(
            flows.iter().map(|f| f.id).collect::<Vec<_>>(),
            (1..=100).collect::<Vec<_>>()
        );
        for (p, id) in ids.iter().enumerate() {
            let f = flows.iter().find(|f| f.id == *id).unwrap();
            assert_eq!(f.tuple.sport, p as i64);
        }
    }
}
