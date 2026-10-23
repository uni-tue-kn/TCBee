//! The grammar of the flags that pick items of a set by name, `--tp` and `--sock-hooks`:
//!
//! - a comma-separated list of names is the set, e.g. `probe,rto`;
//! - a list of only `+name` and `-name` items changes the default set, e.g. `+drops,-probe`;
//! - in a mixed list, the plain names are the set that the `+`/`-` items change, e.g.
//!   `probe,+drops` or `all,-drops`;
//! - `all` names every item, `default` the default set;
//! - `_` and `-` are the same in names (`ca_state` is `ca-state`);
//! - a list that selects nothing is an error.

use std::fmt;

/// A set of named items that a list flag selects
pub trait NamedSet: Copy {
    type Item: Copy + 'static;
    /// What an item is, for messages, e.g. "hook"
    const KIND: &'static str;
    /// Every item, `all`
    const ITEMS: &'static [Self::Item];

    fn item_name(item: Self::Item) -> &'static str;
    fn empty() -> Self;
    fn with(self, item: Self::Item) -> Self;
    fn without(self, item: Self::Item) -> Self;
    fn contains(self, item: Self::Item) -> bool;
    fn is_empty(self) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListError {
    /// A name that is neither an item nor a keyword
    Unknown {
        kind: &'static str,
        name: String,
        names: Vec<&'static str>,
    },
    /// The list selects no item
    Empty { kind: &'static str },
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListError::Unknown { kind, name, names } => write!(
                f,
                "unknown {kind} {name:?}, expected all, default or one of: {}",
                names.join(", ")
            ),
            ListError::Empty { kind } => write!(f, "no {kind} selected"),
        }
    }
}

impl std::error::Error for ListError {}

/// Whether `name` names the item named `item`, with `_` and `-` the same
fn same_name(name: &str, item: &str) -> bool {
    let unify = |c: u8| if c == b'_' { b'-' } else { c };
    name.len() == item.len()
        && name
            .bytes()
            .zip(item.bytes())
            .all(|(a, b)| unify(a) == unify(b))
}

/// The items a name or keyword selects
fn select<S: NamedSet>(name: &str, default: S) -> Result<Vec<S::Item>, ListError> {
    match name {
        "all" => Ok(S::ITEMS.to_vec()),
        "default" => Ok(S::ITEMS
            .iter()
            .copied()
            .filter(|item| default.contains(*item))
            .collect()),
        name => S::ITEMS
            .iter()
            .copied()
            .find(|item| same_name(name, S::item_name(*item)))
            .map(|item| vec![item])
            .ok_or_else(|| ListError::Unknown {
                kind: S::KIND,
                name: name.to_string(),
                names: S::ITEMS.iter().map(|item| S::item_name(*item)).collect(),
            }),
    }
}

/// Parses a list flag, see the module documentation. `default` is the set that `default`
/// names and that a list of only changes starts from.
pub fn parse<S: NamedSet>(spec: &str, default: S) -> Result<S, ListError> {
    let (changes, names): (Vec<&str>, Vec<&str>) = spec
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .partition(|item| item.starts_with(['+', '-']));
    if names.is_empty() && changes.is_empty() {
        return Err(ListError::Empty { kind: S::KIND });
    }
    let mut set = if names.is_empty() {
        default
    } else {
        S::empty()
    };
    for name in names {
        for item in select(name, default)? {
            set = set.with(item);
        }
    }
    for change in changes {
        let (sign, name) = change.split_at(1);
        for item in select(name, default)? {
            set = if sign == "-" {
                set.without(item)
            } else {
                set.with(item)
            };
        }
    }
    if set.is_empty() {
        return Err(ListError::Empty { kind: S::KIND });
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Letters(u8);

    impl NamedSet for Letters {
        type Item = u8;
        const KIND: &'static str = "letter";
        const ITEMS: &'static [u8] = &[0, 1, 2, 3];

        fn item_name(item: u8) -> &'static str {
            ["a", "b", "c_d", "e"][item as usize]
        }
        fn empty() -> Letters {
            Letters(0)
        }
        fn with(self, item: u8) -> Letters {
            Letters(self.0 | 1 << item)
        }
        fn without(self, item: u8) -> Letters {
            Letters(self.0 & !(1 << item))
        }
        fn contains(self, item: u8) -> bool {
            self.0 & 1 << item != 0
        }
        fn is_empty(self) -> bool {
            self.0 == 0
        }
    }

    /// a and b
    const DEFAULT: Letters = Letters(0b0011);

    fn parsed(spec: &str) -> Result<u8, ListError> {
        parse(spec, DEFAULT).map(|set| set.0)
    }

    #[test]
    fn plain_names_are_the_set() {
        assert_eq!(parsed("e"), Ok(0b1000));
        assert_eq!(parsed(" a, e ,a"), Ok(0b1001));
        assert_eq!(parsed("all"), Ok(0b1111));
        assert_eq!(parsed("default"), Ok(0b0011));
        assert_eq!(parsed("default,e"), Ok(0b1011));
    }

    #[test]
    fn changes_alone_change_the_default() {
        assert_eq!(parsed("+e"), Ok(0b1011));
        assert_eq!(parsed("-a,+c_d"), Ok(0b0110));
        assert_eq!(parsed("+all,-b"), Ok(0b1101));
    }

    #[test]
    fn changes_in_a_mixed_list_change_its_names() {
        assert_eq!(parsed("e,+a"), Ok(0b1001));
        assert_eq!(parsed("-e,all"), Ok(0b0111));
        assert_eq!(parsed("all,-default"), Ok(0b1100));
    }

    #[test]
    fn underscore_and_dash_are_the_same() {
        assert_eq!(parsed("c-d"), Ok(0b0100));
        assert_eq!(parsed("c_d"), Ok(0b0100));
        assert_eq!(parsed("+c-d"), Ok(0b0111));
        assert!(parsed("cd").is_err());
    }

    #[test]
    fn errors() {
        assert_eq!(
            parsed("a,x"),
            Err(ListError::Unknown {
                kind: "letter",
                name: "x".into(),
                names: vec!["a", "b", "c_d", "e"],
            })
        );
        assert!(parsed("+x").is_err());
        assert_eq!(parsed(""), Err(ListError::Empty { kind: "letter" }));
        assert_eq!(parsed(" , "), Err(ListError::Empty { kind: "letter" }));
        assert_eq!(parsed("-a,-b"), Err(ListError::Empty { kind: "letter" }));
        assert_eq!(parsed("a,-a"), Err(ListError::Empty { kind: "letter" }));
        assert_eq!(
            ListError::Empty { kind: "hook" }.to_string(),
            "no hook selected"
        );
    }
}
