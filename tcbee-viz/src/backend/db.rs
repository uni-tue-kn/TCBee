use std::path::PathBuf;

use ts_storage::{
    database_factory, DBBackend, DataPoint, DataValue, Flow, TSDBInterface, TimeSeries,
};

use crate::data::series_data::SeriesData;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataSource {
    Sqllite,
    DuckDB,
}

impl std::fmt::Display for DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSource::Sqllite => write!(f, "SQLite"),
            DataSource::DuckDB => write!(f, "DuckDB"),
        }
    }
}

pub struct DbBackend {
    pub interface: Option<Box<dyn TSDBInterface>>,
    pub path: Option<PathBuf>,
    pub source: Option<DataSource>,
}

impl Default for DbBackend {
    fn default() -> Self {
        Self {
            interface: None,
            path: None,
            source: None,
        }
    }
}

impl DbBackend {
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let path_str = path.to_string_lossy().to_string();

        let (interface, source): (Box<dyn TSDBInterface>, DataSource) = match ext {
            "sqlite" => {
                let db = database_factory(DBBackend::SQLite(path_str))
                    .map_err(|e| format!("SQLite open failed: {:?}", e))?;
                (db, DataSource::Sqllite)
            }
            "duck" => {
                let db = database_factory(DBBackend::DuckDB(path_str))
                    .map_err(|e| format!("DuckDB open failed: {:?}", e))?;
                (db, DataSource::DuckDB)
            }
            other => return Err(format!("Unknown extension: {}", other)),
        };

        Ok(Self {
            interface: Some(interface),
            path: Some(path),
            source: Some(source),
        })
    }

    pub fn is_connected(&self) -> bool {
        self.interface.is_some()
    }

    pub fn list_flows(&self) -> Vec<Flow> {
        let Some(db) = &self.interface else {
            return Vec::new();
        };
        db.list_flows()
            .ok()
            .map(|it| it.collect())
            .unwrap_or_default()
    }

    pub fn list_series_for_flow(&self, flow: &Flow) -> Vec<TimeSeries> {
        let Some(db) = &self.interface else {
            return Vec::new();
        };
        db.list_time_series(flow)
            .ok()
            .map(|it| it.collect())
            .unwrap_or_default()
    }

    pub fn get_flow_by_id(&self, id: i64) -> Option<Flow> {
        self.interface.as_ref()?.get_flow_by_id(id).ok().flatten()
    }

    pub fn get_series_by_id(&self, id: i64) -> Option<TimeSeries> {
        self.interface
            .as_ref()?
            .get_time_series_by_id(id)
            .ok()
            .flatten()
    }

    /// Returns (t_min, t_max) for the given flow, or None if unavailable.
    pub fn get_flow_x_bounds(&self, flow_id: i64) -> Option<(f64, f64)> {
        let db = self.interface.as_ref()?;
        let flow = db.get_flow_by_id(flow_id).ok()??;
        let mut t_min = f64::MAX;
        let mut t_max = f64::MIN;
        let all = db.list_time_series(&flow).ok()?;

        for series in all {
            let Ok(count) = db.get_data_points_count(&series) else {
                continue;
            };
            if count == 0 {
                continue;
            }
            let Ok(bounds) = db.get_time_series_bounds(&series) else {
                continue;
            };
            t_min = t_min.min(bounds.xmin);
            t_max = t_max.max(bounds.xmax);
        }

        if t_min > t_max {
            None
        } else {
            Some((t_min, t_max))
        }
    }

    /// Returns (y_min, y_max) across all given series IDs.
    pub fn get_series_y_bounds(&self, series_ids: &[i64]) -> Option<(f64, f64)> {
        let db = self.interface.as_ref()?;
        let mut y_min = f64::MAX;
        let mut y_max = f64::MIN;

        for &id in series_ids {
            let series = db.get_time_series_by_id(id).ok()??;
            let bounds = db.get_time_series_bounds(&series).ok()?;
            if let (Some(lo), Some(hi)) = (&bounds.ymin, &bounds.ymax) {
                if let Some(lo_f) = datavalue_as_f64(lo) {
                    y_min = y_min.min(lo_f);
                }
                if let Some(hi_f) = datavalue_as_f64(hi) {
                    y_max = y_max.max(hi_f);
                }
            }
        }

        if y_min > y_max {
            None
        } else {
            Some((y_min, y_max))
        }
    }

    /// Load numeric points in a time range, keeping at most one point per sample interval.
    pub fn load_range_sampled(
        &self,
        series_id: i64,
        t_min: f64,
        t_max: f64,
        sample_interval: f64,
    ) -> Vec<(f64, f64)> {
        let Some(db) = &self.interface else {
            return Vec::new();
        };
        let Some(series) = db.get_time_series_by_id(series_id).ok().flatten() else {
            return Vec::new();
        };
        let Ok(iter) = db.get_data_points_in_range(&series, t_min, t_max) else {
            return Vec::new();
        };

        let mut next_timestamp = f64::NEG_INFINITY;
        iter.filter_map(|p| {
            let value = datavalue_as_f64(&p.value)?;
            if sample_interval <= 0.0 || p.timestamp >= next_timestamp {
                next_timestamp = p.timestamp + sample_interval;
                Some((p.timestamp, value))
            } else {
                None
            }
        })
        .collect()
    }

    /// Load string points in a time range, keeping at most one point per sample interval.
    pub fn load_range_strings_sampled(
        &self,
        series_id: i64,
        t_min: f64,
        t_max: f64,
        sample_interval: f64,
    ) -> Vec<(f64, String)> {
        let Some(db) = &self.interface else {
            return Vec::new();
        };
        let Some(series) = db.get_time_series_by_id(series_id).ok().flatten() else {
            return Vec::new();
        };
        let Ok(iter) = db.get_data_points_in_range(&series, t_min, t_max) else {
            return Vec::new();
        };

        let mut next_timestamp = f64::NEG_INFINITY;
        iter.filter_map(|p| {
            if let DataValue::String(s) = p.value {
                if sample_interval <= 0.0 || p.timestamp >= next_timestamp {
                    next_timestamp = p.timestamp + sample_interval;
                    Some((p.timestamp, s))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
    }

    /// Load true boolean events in a time range, keeping at most one event per sample interval.
    pub fn load_range_bool_events_sampled(
        &self,
        series_id: i64,
        t_min: f64,
        t_max: f64,
        sample_interval: f64,
    ) -> Vec<(f64, f64)> {
        let Some(db) = &self.interface else {
            return Vec::new();
        };
        let Some(series) = db.get_time_series_by_id(series_id).ok().flatten() else {
            return Vec::new();
        };
        let Ok(iter) = db.get_data_points_in_range(&series, t_min, t_max) else {
            return Vec::new();
        };

        let mut next_timestamp = f64::NEG_INFINITY;
        iter.filter_map(|p| {
            let DataValue::Boolean(true) = p.value else {
                return None;
            };
            if sample_interval <= 0.0 || p.timestamp >= next_timestamp {
                next_timestamp = p.timestamp + sample_interval;
                Some((p.timestamp, 1.0))
            } else {
                None
            }
        })
        .collect()
    }

    /// Load ALL data points for a series (used by plugins — they need the full dataset).
    pub fn load_all(&self, series_id: i64) -> Vec<(f64, DataValue)> {
        let Some(db) = &self.interface else {
            return Vec::new();
        };
        let Some(series) = db.get_time_series_by_id(series_id).ok().flatten() else {
            return Vec::new();
        };
        let Ok(iter) = db.get_data_points(&series) else {
            return Vec::new();
        };
        iter.map(|p| (p.timestamp, p.value)).collect()
    }

    /// Persist a newly computed series for a flow into the database.
    pub fn create_series_for_flow(&self, flow: &Flow, series: &SeriesData) -> Result<(), String> {
        let db = self.interface.as_ref().ok_or("No database connection")?;

        let ts = db
            .create_time_series(flow, &series.name, series.val_type.clone())
            .map_err(|e| format!("create_time_series failed: {:?}", e))?;

        let points: Vec<DataPoint> = series
            .raw_data
            .iter()
            .map(|(t, v)| DataPoint {
                timestamp: *t,
                value: v.clone(),
            })
            .collect();

        db.insert_multiple_points(&ts, &points)
            .map_err(|e| format!("insert_multiple_points failed: {:?}", e))?;

        Ok(())
    }

    /// Delete an existing series with the same name, then persist the computed replacement.
    pub fn replace_series_for_flow(&self, flow: &Flow, series: &SeriesData) -> Result<(), String> {
        let db = self.interface.as_ref().ok_or("No database connection")?;

        for existing in self.existing_series_for_flow(flow, &[series.name.clone()])? {
            db.delete_time_series(flow, &existing)
                .map_err(|e| format!("delete_time_series failed: {:?}", e))?;
        }

        self.create_series_for_flow(flow, series)
    }

    pub fn existing_series_for_flow(
        &self,
        flow: &Flow,
        names: &[String],
    ) -> Result<Vec<TimeSeries>, String> {
        let db = self.interface.as_ref().ok_or("No database connection")?;
        let all = db
            .list_time_series(flow)
            .map_err(|e| format!("list_time_series failed: {:?}", e))?;
        Ok(all
            .filter(|series| names.iter().any(|name| series.name == *name))
            .collect())
    }

    /// Return the total number of data points for a series.
    pub fn get_point_count(&self, series_id: i64) -> i64 {
        let Some(db) = &self.interface else { return 0 };
        let Some(series) = db.get_time_series_by_id(series_id).ok().flatten() else {
            return 0;
        };
        db.get_data_points_count(&series).unwrap_or(0)
    }
}

pub fn datavalue_as_f64(v: &DataValue) -> Option<f64> {
    match v {
        DataValue::Float(f) => Some(*f),
        DataValue::Int(i) => Some(*i as f64),
        DataValue::Boolean(b) => Some(if *b { 1.0 } else { 0.0 }),
        DataValue::String(_) => None,
    }
}

pub fn format_flow(flow: &Flow) -> String {
    format!(
        "ID:{} {}:{} → {}:{}",
        flow.id, flow.tuple.src, flow.tuple.sport, flow.tuple.dst, flow.tuple.dport,
    )
}
