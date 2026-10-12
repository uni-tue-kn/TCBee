//! The parts of the MPTCP tab that do not draw: which end of a connection a recording shows,
//! the sidebar rows and their filter.

/// Which end of an MPTCP connection the recording shows
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
    /// Guessed from the lower port being the server's
    LikelyClient,
    LikelyServer,
}

impl Side {
    pub fn label(self) -> &'static str {
        match self {
            Side::Client => "client",
            Side::Server => "server",
            Side::LikelyClient => "client?",
            Side::LikelyServer => "server?",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Side::Client | Side::Server => {
                "From the token of the other end that the client's joins carry"
            }
            Side::LikelyClient | Side::LikelyServer => {
                "Guessed: the side of the port that every subflow shares, or else the lower port"
            }
        }
    }
}

/// What `infer_sides` needs of one connection
#[derive(Clone, Debug, Default)]
pub struct SideInput {
    /// The local token
    pub key: i64,
    /// Tokens of the other end that its subflows' path manager records carry (0 = none)
    pub remote_tokens: Vec<i64>,
    /// (local port, remote port) of each subflow
    pub ports: Vec<(i64, i64)>,
}

/// The side of each connection and the index of its other end, if both ends were recorded.
///
/// The joins of a client carry the server's token, which settles both ends. Otherwise the
/// server's port is the one that all subflows share (the listening port), and if that does
/// not decide, the lower port.
pub fn infer_sides(connections: &[SideInput]) -> Vec<(Option<Side>, Option<usize>)> {
    let mut out: Vec<(Option<Side>, Option<usize>)> = vec![(None, None); connections.len()];
    for (client, c) in connections.iter().enumerate() {
        let peer = c.remote_tokens.iter().filter(|t| **t != 0).find_map(|t| {
            connections
                .iter()
                .position(|other| other.key == *t)
                .filter(|server| *server != client)
        });
        if let Some(server) = peer {
            out[client] = (Some(Side::Client), Some(server));
            out[server] = (Some(Side::Server), Some(client));
        }
    }
    for (i, c) in connections.iter().enumerate() {
        if out[i].0.is_none() {
            out[i].0 = side_from_ports(&c.ports);
        }
    }
    out
}

fn side_from_ports(ports: &[(i64, i64)]) -> Option<Side> {
    let &(local, remote) = ports.first()?;
    let local_shared = ports.iter().all(|p| p.0 == local);
    let remote_shared = ports.iter().all(|p| p.1 == remote);
    Some(match (local_shared, remote_shared) {
        (true, false) => Side::LikelyServer,
        (false, true) => Side::LikelyClient,
        _ if local < remote => Side::LikelyServer,
        _ => Side::LikelyClient,
    })
}

/// One MPTCP connection in the sidebar table
#[derive(Clone, Debug)]
pub struct ConnectionSummary {
    pub id: i64,
    pub token: i64,
    /// local -> remote of the first subflow
    pub first_subflow: String,
    pub side: Option<Side>,
    /// Connection id of the other end, if recorded too
    pub peer: Option<i64>,
    pub subflows: usize,
    /// Path manager records on the subflows' tuples
    pub events: i64,
    pub start_s: f64,
    pub duration_s: f64,
}

impl ConnectionSummary {
    pub fn token_text(&self) -> String {
        format!("{:#010x}", self.token)
    }

    /// Whether the row matches every whitespace-separated term of a lowercase filter
    pub fn matches(&self, filter: &str) -> bool {
        let text = format!(
            "#{} {} {} {} {}",
            self.id,
            self.token_text(),
            self.token,
            self.first_subflow,
            self.side.map_or("", Side::label)
        )
        .to_lowercase();
        filter.split_whitespace().all(|term| text.contains(term))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(key: i64, remote_tokens: &[i64], ports: &[(i64, i64)]) -> SideInput {
        SideInput {
            key,
            remote_tokens: remote_tokens.to_vec(),
            ports: ports.to_vec(),
        }
    }

    #[test]
    fn remote_token_settles_both_ends() {
        // e6: the client's join carries the server's token; ports alone would also work
        let sides = infer_sides(&[
            input(0x3fa1, &[0, 0x5a4b], &[(55872, 5501), (58139, 5501)]),
            input(0x5a4b, &[0], &[(5501, 55872), (5501, 58139)]),
        ]);
        assert_eq!(sides[0], (Some(Side::Client), Some(1)));
        assert_eq!(sides[1], (Some(Side::Server), Some(0)));
    }

    #[test]
    fn remote_token_beats_ports() {
        // Joins to a signal endpoint on another port: neither end shares a port
        let sides = infer_sides(&[
            input(7, &[9], &[(40000, 5501), (40001, 6000)]),
            input(9, &[], &[(5501, 40000), (6000, 40001)]),
        ]);
        assert_eq!(sides[0].0, Some(Side::Client));
        assert_eq!(sides[1].0, Some(Side::Server));
    }

    #[test]
    fn shared_port_without_token() {
        let sides = infer_sides(&[
            input(1, &[], &[(5501, 40000), (5501, 40001)]),
            input(2, &[], &[(40000, 5501), (40001, 5501)]),
        ]);
        assert_eq!(sides[0], (Some(Side::LikelyServer), None));
        assert_eq!(sides[1], (Some(Side::LikelyClient), None));
    }

    #[test]
    fn single_subflow_falls_back_to_the_lower_port() {
        // A fallback to TCP has one subflow and no joins
        let sides = infer_sides(&[
            input(1, &[], &[(43959, 5501)]),
            input(2, &[], &[(80, 51000)]),
        ]);
        assert_eq!(sides[0].0, Some(Side::LikelyClient));
        assert_eq!(sides[1].0, Some(Side::LikelyServer));
    }

    #[test]
    fn unknown_or_own_token_is_ignored() {
        let sides = infer_sides(&[input(5, &[5, 77], &[]), input(6, &[], &[])]);
        assert_eq!(sides, vec![(None, None), (None, None)]);
    }

    #[test]
    fn filter_matches_all_terms() {
        let row = ConnectionSummary {
            id: 2,
            token: 0x5a4bd6e2,
            first_subflow: "10.31.1.2:5501 -> 10.31.1.1:55872".into(),
            side: Some(Side::Server),
            peer: Some(1),
            subflows: 3,
            events: 12,
            start_s: 0.05,
            duration_s: 22.4,
        };
        assert!(row.matches(""));
        assert!(row.matches("0x5a4b server"));
        assert!(row.matches("10.31.1.1 #2"));
        assert!(row.matches(&0x5a4bd6e2_i64.to_string()));
        assert!(!row.matches("client"));
        assert!(!row.matches("5501 10.99"));
    }
}
