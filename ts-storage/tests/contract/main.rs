//! Contract tests of the storage API, run on every enabled engine.
//!
//! Every function in `cases.rs` takes an `Engine` and runs against a temp file through the public
//! API only (`create`, `open`, `Store`, ...). The macros below instantiate each case
//! once per enabled engine. `equivalence.rs` runs one script on both engines and compares
//! everything observable through `Store`. Engine specific code (old-schema files with the raw
//! drivers, disabled engines) lives in `fixture.rs` and at the end of `cases.rs`.

#![cfg(any(feature = "sqlite", feature = "duckdb"))]

/// Asserts that an expression is `Err(<pattern>)`, printing the actual result otherwise.
macro_rules! assert_err {
    ($e:expr, $pat:pat $(if $guard:expr)?) => {{
        let r = $e;
        assert!(
            matches!(r, Err($pat) $(if $guard)?),
            "expected {}, got {:?}",
            stringify!($pat),
            r.as_ref().err()
        );
    }};
}

/// Generates `#[test] fn <case>() { cases::<case>($engine) }` for each case in a module.
macro_rules! instantiate {
    ($module:ident, $engine:expr; $($case:ident)*) => {
        mod $module {
            use super::*;
            $(
                #[test]
                fn $case() {
                    cases::$case($engine)
                }
            )*
        }
    };
}

/// The list of engine independent cases, instantiated for one engine.
macro_rules! all_cases {
    ($module:ident, $engine:expr) => {
        instantiate!($module, $engine;
            round_trip_integers_and_bools
            round_trip_floats
            round_trip_text
            u64_saturates_in_the_catalog
            engine_is_detected
            points_are_ordered_by_ts_then_seq
            ranges_are_inclusive
            ranges_round_inward
            ranges_outside_or_empty
            ranges_with_non_finite_bounds
            several_batches_and_writers
            two_writers_append_to_one_table_and_flow
            catalog_flows_by_tuple
            catalog_series_per_flow
            catalog_same_name_differs_by_dir
            catalog_stats_match_brute_force
            catalog_ids_and_references
            derived_create_and_read
            derived_timestamps_are_rounded
            derived_replace_keeps_the_id
            derived_replace_with_nothing
            derived_delete
            derived_survives_reopen
            derived_strings
            derived_nan_value_round_trips
            derived_bool_float_int
            derived_duplicate_name_exists
            derived_name_may_repeat_across_flows_and_raw_names
            derived_wrong_value_kind_is_a_type_mismatch
            derived_non_finite_timestamp_is_a_type_mismatch
            derived_failed_replace_keeps_the_old_series
            raw_series_cannot_be_replaced
            raw_series_cannot_be_deleted
            fake_derived_info_of_a_raw_series_is_not_derived
            missing_series_is_not_found
            stale_series_is_not_found
            nan_in_an_event_column_is_rejected
            abandoned_session_leaves_nothing
            abandoned_session_with_a_live_writer_leaves_nothing
            finished_file_has_no_sidecars
            existing_file_needs_force
            force_keeps_the_old_file_until_finish
            force_replaces_the_file_on_finish
            schema_v1_file_is_unsupported
        );
    };
}

mod cases;
#[cfg(all(feature = "sqlite", feature = "duckdb"))]
mod equivalence;
mod fixture;

use ts_storage::Engine;

#[cfg(feature = "sqlite")]
all_cases!(sqlite, Engine::Sqlite);
// A module named `duckdb` would be fine here; `fixture.rs` names the driver crate by path.
#[cfg(feature = "duckdb")]
all_cases!(duckdb, Engine::DuckDb);

#[test]
fn non_database_files_are_unknown() {
    cases::non_database_files_are_unknown();
}

#[cfg(not(feature = "duckdb"))]
#[test]
fn duckdb_file_with_the_engine_disabled() {
    cases::file_of_a_disabled_engine(Engine::DuckDb);
}

#[cfg(not(feature = "sqlite"))]
#[test]
fn sqlite_file_with_the_engine_disabled() {
    cases::file_of_a_disabled_engine(Engine::Sqlite);
}
