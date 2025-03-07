// logic for backend implementation of program
// manages and defines access to database / which source to use etc.

use crate::modules::{
    backend::plot_data_preprocessing::generate_n_random_colors,
    ui::{
        lib_styling::app_style_settings::{DEFAULT_Y_MAX, DEFAULT_Y_MIN},
        lib_widgets::lib_graphs::{
            struct_flow_series_data::FlowSeriesData,
            struct_processed_plot_data::ProcessedPlotData,
            struct_zoom_bounds::{retrieve_default_zoom_for_one_flow, ZoomBound, ZoomBound2D},
        },
    },
};

use crate::TSDBInterface;
use iced::widget::canvas::Cache;
use plotters::style::RGBAColor;
use ts_storage::{database_factory, sqlite::SQLiteTSDB, DBBackend, DataValue, Flow};
use ts_storage::{DataPoint, TimeSeries};
use std::{cell::RefCell, f64::{MAX, MIN}, path::PathBuf, slice::Iter, sync::RwLock};

// testing to adapt to issue of not refrencing well enough?
use std::sync::Arc;

use super::{app_settings::ApplicationSettings, struct_tcp_flow_wrapper::TcpFlowWrapper};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataSource {
    Influx,
    Sqllite,
    None,
}

impl DataSource {
    pub const ALL: &'static [Self] = &[Self::Influx, Self::Sqllite, Self::None];
    //https://stackoverflow.com/questions/21371534/in-rust-is-there-a-way-to-iterate-through-the-values-of-an-enum
    pub fn iterator() -> Iter<'static, DataSource> {
        DataSource::ALL.iter()
    }
}

impl ToString for DataSource {
    fn to_string(&self) -> String {
        match self {
            DataSource::Influx => String::from("Influx"),
            DataSource::Sqllite => String::from("Sqllite"),
            DataSource::None => String::from("Nothing selected"),
        }
    }
}

pub struct IntermediateBackend {
    pub source_type: DataSource,
    pub database_interface: Option<Arc<Box<dyn TSDBInterface>>>,
    pub database_path: Option<PathBuf>,
}

impl IntermediateBackend {
    pub fn receive_active_flow_bounds_x(&self, active_flow_id: &Option<i64>) -> Option<ZoomBound> {
        match active_flow_id {
            Some(value) => {
                // if it was selected we know that its available!
                let db_connection = self.database_interface.clone().unwrap();
                let flow = db_connection.get_flow_by_id(*value).unwrap().unwrap();
                let maybe_bounds = db_connection
                    .get_flow_bounds(&flow);
                match maybe_bounds{
                    Ok(boundaries) => {
                        Some(ZoomBound {
                            lower: boundaries.xmin,
                            upper: boundaries.xmax,
                        })
                    }
                    _ => None 
                }
            }
            _ => None,
        }
    }

    pub fn receive_active_series_max_bounds(
        &self,
        collection_of_series: Option<Vec<i64>>,
    ) -> Option<ZoomBound> {
        if let Some(series) = self.receive_active_timeseries(collection_of_series) {
            let db_connection = self.database_interface.clone().unwrap();

            let mut lowest_y: f64 = MAX;
            let mut highest_y: f64 = MIN;
            for series_id in series {
                let boundaries = db_connection
                    .get_time_series_bounds(&series_id)
                    .expect("could not receive boundaries");
                if let (Some(y_min),Some(y_max)) = (&boundaries.ymin , &boundaries.ymax) {
                    let lower = y_min;
                    let upper = y_max;
                    // guaranteed to be DataValue
                    match series_id.ts_type {
                        DataValue::Float(_) => {
                            //  comparing
                            lowest_y = lowest_y.min(lower.as_float().unwrap());
                            highest_y = highest_y.max(upper.as_float().unwrap());
                        }
                        DataValue::Int(_) => {
                            lowest_y = lowest_y.min(lower.as_int().unwrap() as f64);
                            highest_y = highest_y.max(upper.as_int().unwrap() as f64);
                        }
                        // FIXME maybe also setting for Boolean / Strings?
                        _ => {}
                    }
                }
            }

            // println!("Debug: y boundaries are:\n low:{:?}\n high: {:?}",lowest_y,highest_y);
            if lowest_y == highest_y {
                // ASSUME: found constant, hence creating new boundaries
                let old_constant = lowest_y;
                lowest_y = old_constant - 10.0;
                highest_y = old_constant + 10.0;
            }
            
            return Some(ZoomBound {
                lower: lowest_y,
                upper: highest_y,
            });
        }
        None
    }

    /// requests the given series-ids from the database-interface
    /// returns a vector of those, None if the connection is not established
    pub fn receive_active_timeseries(
        &self,
        collection_of_series: Option<Vec<i64>>,
    ) -> Option<Vec<TimeSeries>> {
        if let Some(db_connection) = &self.database_interface {
            let mut list_of_time_series: Vec<TimeSeries> = Vec::new();

            if collection_of_series.is_none() {
                return None;
            }
            for id in collection_of_series.unwrap() {
                let maybe_series = db_connection.get_time_series_by_id(id);
                match maybe_series {
                    Ok(value) => {
                        // FIXME: are we sure that this will be Some()
                        list_of_time_series.push(value.unwrap());
                    }
                    _ => {}
                }
            }

            return Some(list_of_time_series);
        }
        None
    }

    pub fn receive_selected_flow(&self, active_flow: Option<i64>) -> Option<Flow> {
        if let Some(db_connection) = &self.database_interface {
            let active_flow_id = active_flow;
            //  DEBUG
            // println!("received active flow_id {:?}",active_flow_id);
            match active_flow_id {
                Some(id) => {
                    // OPTIONAL maybe clone instead of dereferencing?
                    let active_flow = db_connection.get_flow_by_id(id);
                    return active_flow.expect("flow could not be received");
                }
                _ => {
                    return None;
                }
            }
        }
        // nothing found, not displaying anything
        None
    }

    /// takes iterator over TimeSeries and collection of strings representing names of TimeSeries
    /// returns maybe filtered list of ids for required time_series
    /// INVARIANT: Requires returned list of ids to be the same size as list of names
    /// returns None otherwise
    pub fn filter_timeseries_on_name(
        iterator: Box<dyn Iterator<Item = TimeSeries>>,
        vec_of_names: Vec<String>,
    ) -> Vec<i64> {
        let filtered_entries: Vec<i64> = iterator
            .into_iter()
            .filter(|entry| {
                if vec_of_names.contains(&entry.name) {
                    true
                } else {
                    false
                }
            })
            .map(|entry| {
                // FIXME: could crash if now ids is defined for the given timeseries
                entry
                    .id
                    .expect(format!("receiving id of series {:?} failed", entry.name).as_str())
            })
            .collect();

        filtered_entries
    }

    // CONSIDERATION: could also be passed a TcpFlowWrapper struct --> yet not necessary!
    // FIXME: add Result as return type!
    pub fn receive_series_id_from_string_and_flow_id(
        &self,
        active_flow: i64,
        collection_of_strings: Vec<String>,
    ) -> Result<Option<Vec<i64>>, String> {
        let maybe_flow = self.receive_selected_flow(Some(active_flow));
        if let Some(flow) = maybe_flow {
            // ASSUMPTION: db connection should be available
            let db_connection = self.database_interface.as_ref().unwrap();
            // FIXME: remove unwrap --> pass to function instead
            let available_series = db_connection.list_time_series(&flow).unwrap();
            let collected_ids: Vec<i64> = available_series
                .into_iter()
                .filter(|entry| {
                    if collection_of_strings.contains(&entry.name) {
                        true
                    } else {
                        false
                    }
                })
                .map(|entry| entry.id.expect("could not parse id from timerseries given"))
                .collect();

            if collected_ids.len() != collection_of_strings.len() {
                Err(format!("amount of received ids does not match requested amount, maybe database does not contain the time series?, values were {:?}",collected_ids))
            } else {
                Ok(Some(collected_ids))
            }

        // let filtered_entries_as_id = IntermediateBackend::filter_timeseries_on_name(&available_series,collection_of_strings);
        // Some(filtered_entries_as_id)
        } else {
            Err("No Flow found, aborting".to_string())
        }
    }

    // DEBUG
    pub fn receive_flow_formatted(&self, flow: &Flow) -> String {
        format!(
            "ID:{:?} Port: (src: {:?}) IP(src: {:?} : dst: {:?}) ",
            flow.get_id().unwrap(),
            flow.tuple.sport,
            flow.tuple.src,
            flow.tuple.dst
        )
    }
}

// we clone here and therefore give this cloned version the same lifetime
// as the original we referenced from!
// we add <'a> for the impl keyword to:
// -giving the compiler information that this is the implementation for the struct with a lifetime!
impl Clone for IntermediateBackend {
    fn clone(&self) -> Self {
        IntermediateBackend {
            source_type: self.source_type.clone(),
            database_interface: self.database_interface.clone(),
            database_path: self.database_path.clone(),
        }
    }
}

impl IntermediateBackend {
    pub fn new(source: DataSource, path_db: String) -> Self {
        match source {
            DataSource::Sqllite => {
                let db_interface: Arc<Box<dyn TSDBInterface>> = Arc::new(
                    database_factory::<SQLiteTSDB>(DBBackend::SQLite(path_db.clone()))
                        .expect("could not parse database"),
                );
                println!("initialized database of time {:?}", source);
                IntermediateBackend {
                    source_type: source.clone(),
                    database_interface: Some(db_interface),
                    database_path: Some(PathBuf::from(path_db))
                }
            }
            _ => IntermediateBackend {
                source_type: source.clone(),
                database_interface: None,
                database_path: None,
                // selected_flow: None,
                // selected_series_attributes: None,
            },
        }
    }

    pub fn create_new_series_for_flow(
        &self,
        flow: &TcpFlowWrapper,
        new_series: &FlowSeriesData,
    ) -> Result<bool, String> {
        let db_interface: Arc<Box<dyn TSDBInterface>> = match &self.database_interface {
            Some(interface) => interface.clone(),
            None => return Err("could not connect to db, aborting".to_string()),
        };
        let flow_id = match flow.flow_id {
            Some(id) => id,
            None => return Err("could not retrieve flow from supplied TcpFlowWrapper".to_string()),
        };
        let maybe_flow = db_interface.get_flow_by_id(flow_id);
        let flow_object = match maybe_flow {
            Ok(Some(flow)) => flow,
            Ok(None) => return Err("flow not found".to_string()),
            Err(error) => {
                return Err(format!(
                    "could not retrieve flow from Db, reasons {:?}",
                    error
                ))
            }
        };

        let maybe_new_timeseries = db_interface.create_time_series(
            &flow_object,
            &new_series.name,
            new_series.data_val_type.clone(),
        );

        let time_series = match maybe_new_timeseries {
            Ok(timeseries) => timeseries,
            Err(error) => {
                return Err(format!(
                    "could not create new timeseries, reasons {:?}",
                    error
                ))
            }
        };

        let collection_of_series_data: Vec<DataPoint> = new_series
            .timestamps
            .iter()
            .zip(&new_series.data)
            .map(|(&new_timestamp, data_value)| DataPoint {
                timestamp: new_timestamp,
                value: data_value.clone(),
            })
            .collect();

        // inserting datapoints
        let result_of_adding_data =
            db_interface.insert_multiple_points(&time_series, &collection_of_series_data);
        match result_of_adding_data {
            Ok(success) => return Ok(success),
            Err(error) => {
                return Err(format!(
                    "could not insert data to new timeseries, reasons {:?}",
                    error
                ))
            }
        }
    }

    /// pre-processor fetching data to display
    /// returns vector wher each entry is a data point to plot
    /// FIXME refactor too!
    pub fn collect_data_to_visualize(
        &self,
        app_reference: &Arc<RwLock<ApplicationSettings>>,
        selected_flow: TcpFlowWrapper,
        active_split_chart_height: f32,
    ) -> Option<ProcessedPlotData> {
        // OPTIONAL: add limits for how much to collect here!
        println!("Debug: attempting to create ProcessedPlotData");

        // let backend_interface = &read_settings.intermediate_interface;
        let db_interface: Arc<Box<dyn TSDBInterface>> = self
            .database_interface
            .clone()
            .expect("could not connect to database");

        let flow_timestamp_bounds = self
            .receive_active_flow_bounds_x(&selected_flow.flow_id)
            .unwrap_or_default();

        let zoom_range = retrieve_default_zoom_for_one_flow(app_reference, &selected_flow);

        // --- gathering data ---
        //  receiving active series to query from
        let maybe_time_series =
            self.receive_active_timeseries(selected_flow.clone().selected_series);
        let available_time_series = match maybe_time_series {
            Some(value) => value,
            _ => {
                return None;
            }
        };
        // --- COLOR Generation
        let colors_to_generate = available_time_series.len();
        let mut colors_for_series = generate_n_random_colors(colors_to_generate);

        let collection_of_flow_series = self.collect_flowseries_from_timeseries(
            &db_interface,
            available_time_series,
            &mut colors_for_series,
            flow_timestamp_bounds,
            zoom_range.clone(),
            active_split_chart_height,
        );

        let resulting_collection = ProcessedPlotData {
            name: format!("Flow: {:?}", selected_flow.clone().flow_id.unwrap_or(0),),
            point_collection: collection_of_flow_series,
            zoom_bounds: zoom_range.clone(),
            spec_frame: RefCell::new(None),
            draw_point_series: false,
            chart_cache: Cache::new(),
            pressed_cursor: false,
            first_pressed_position: None,
            second_pressed_position: None,
            current_position: None,
            app_settings: app_reference.clone(),
        };
        Some(resulting_collection)
    }

    pub fn collect_flowseries_from_timeseries(
        &self,
        db_interface: &Arc<Box<dyn TSDBInterface>>,
        available_time_series: Vec<TimeSeries>,
        vector_of_colors: &mut Vec<RGBAColor>,
        flow_timestamp_bound: ZoomBound,
        zoom_range: ZoomBound2D,
        split_chart_height: f32,
    ) -> Vec<FlowSeriesData> {
        let mut collection_of_flow_series: Vec<FlowSeriesData> = Vec::new();

        for series in available_time_series {
            let datapoint_iterator = self
                .database_interface
                .as_ref()
                .unwrap()
                .get_data_points(&series)
                .expect(
                    format!("could not receive datapoints from series {:?}", series.name).as_str(),
                );

            let mut time_data: Vec<f64> = Vec::new();
            let mut series_data: Vec<DataValue> = Vec::new();
            for point in datapoint_iterator {
                time_data.push(point.timestamp);
                series_data.push(point.value);
            }
            let series_bounds = db_interface
                .get_time_series_bounds(&series)
                .expect(format!("could not find bounds for {:?}", series.name).as_str());

            let series_data = FlowSeriesData {
                name: series.name.clone(),
                timestamps: time_data,
                data_val_type: series.ts_type.clone(),
                //  FIXME might not be required to save!
                data: series_data,
                // data_iterator:Box::new(db_interface.get_data_points(series).expect("no iterator received")),
                min_val: series_bounds.ymin.clone(),
                max_val: series_bounds.ymax.clone(),
                min_timestamp: flow_timestamp_bound.lower,
                max_timestamp: flow_timestamp_bound.upper,
                zoom_bounds: zoom_range.clone(),
                chart_height: split_chart_height,
                // min_timestamp: graph_range.x.lower,
                // max_timestamp: graph_range.x.upper,
                line_color: vector_of_colors
                    .pop()
                    .expect("could not receive value")
                    .clone(),
                cache: Cache::new(),
            };

            collection_of_flow_series.push(series_data);
        }
        collection_of_flow_series
    }
}
