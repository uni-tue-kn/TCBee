// contains logic for storing / modifying settings of application

// -- internal imports
use crate::modules::backend::intermediate_backend::IntermediateBackend;
use crate::modules::backend::plot_data_preprocessing::ColorScheme;
use crate::DataSource;

// -- external imports
use std::path::PathBuf;

pub struct ApplicationSettings {
    // ---- Visualization | Display-Settings
    pub display_debug: bool,
    pub text_size: u16,

    // ---- Graph-Settings
    pub graph_pointseries_threshold: f64,
    pub datavalue_skip_counter: u32,
    pub reduce_point_density_on_zoom: bool,
    pub amount_to_skip_on_zoom: usize,
    pub graph_pointseries_color_scheme: ColorScheme,

    // ---- Backend | DataSource-Settings
    pub datasource: Option<DataSource>,
    pub database_path: Option<PathBuf>,
    pub intermediate_interface: IntermediateBackend,
}

impl ApplicationSettings {
    pub fn new() -> Self {
        println!("Debug: initializing settings + Database");
        ApplicationSettings {
            text_size: 8,
            display_debug: false,

            // ---- Graph-Settings
            graph_pointseries_threshold: 3.0,
            datavalue_skip_counter: 1,
            reduce_point_density_on_zoom: false,
            amount_to_skip_on_zoom: 400,
            graph_pointseries_color_scheme:ColorScheme::RandomHSL,

            //  ---- Backend | DataSource-Settings
            datasource: None,
            database_path: None,
            intermediate_interface: IntermediateBackend::new(DataSource::None, "".to_string()),
        }
    }

    pub fn set_new_database_connection(&mut self, new_path: PathBuf) {
        // if new_path.extension().unwrap().eq("sqlite"){
        //  valid extension given

        // }
        println!("/// -- creating new database connection");
        self.database_path = Some(new_path.clone());
        self.intermediate_interface = IntermediateBackend::new(
            // FIXME --> it should be given that this source was set!
            self.datasource.expect("no source selected"),
            new_path.as_os_str().to_string_lossy().into_owned(),
        )
    }
}
