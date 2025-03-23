use plotters::style::RGBAColor;

// default values for graph in x and y axis
pub const DEFAULT_Y_MIN: f64 = 0.0;
pub const DEFAULT_Y_MAX: f64 = 10.0;
pub const DEFAULT_X_MIN: f64 = 0.0;
pub const DEFAULT_X_MAX: f64 = 100.0;

// denotes max label sizes for both x and y axis
pub const CHART_X_LABEL_AREA_SIZE: i32 = 40;
pub const CHART_Y_LABEL_AREA_SIZE: i32 = 40;

// denotes margin between Element wrapping around chart and chart
pub const CHART_MARGIN: f64 = 60.0;

// denotes how many labels are displayed on the x-axis at max
pub const CHART_MAX_X_LABELS: usize = 10;

// denotes how many labels are displayd on the y-axis at max
pub const CHART_MAX_Y_LABELS: usize = 50;
pub const CHART_SPLIT_MAX_Y_LABELS: usize = 20;

// denotes inner diameter of a circle to plot
pub const CIRCLE_SIZE: u32 = 2;

// controls steps per movement for zoom sliders
pub const SLIDER_STEP_SIZE: f64 = 0.001;

// changes the amount of points to skip: all but $nth$ entries will be skipped
// i.e. with 4 every fourth element will be kept, all others dropped
pub const AMOUNT_TO_FILTER_FOR_BOOLEAN_VALUES: usize = 200;
pub const AMOUNT_TO_FILTER_FOR_BOOLEAN_VALUES_IN_SPLIT_CHART: usize = 10;

// constants
// FIXME: move to styling instead!
pub const PADDING_AROUND_CONTENT: u16 = 60;
pub const PADDING_BUTTON: u16 = 20;
pub const PADDING_SIDEBAR: u16 = 10;
pub const HOME_LEFT_COL_PORTION: u16 = 1;
pub const HOME_RIGHT_COL_PORTION: u16 = 4;

// TEXTSTYLING
pub const TEXT_HEADLINE_0_SIZE: u16 = 30;
pub const TEXT_HEADLINE_1_SIZE: u16 = 20;
pub const TEXT_HEADLINE_2_SIZE: u16 = 15;
// pub const TEXT_SIZE: u16 = 8;
//  settings for split_charts and their height management
pub const CHART_HEIGHT: f32 = 400.0;

// TEXTCOLORS
// based on rosepinetheme: https://rosepinetheme.com/palette/ingredients/

// TEXT
pub const TEXT_BASE_COLOR: RGBAColor = RGBAColor(224, 222, 244, 1.0);
// FOAM
pub const TEXT_ACCENT_1_COLOR: RGBAColor = RGBAColor(156, 207, 216, 1.0);
// IRIS
pub const TEXT_HEADLINE_COLOR: RGBAColor = RGBAColor(196, 167, 231, 1.0);
// GOLD
pub const TEXT_ACCENT_2_COLOR: RGBAColor = RGBAColor(234, 157, 52, 1.0);

pub const SPLIT_CHART_MIN_HEIGHT: f32 = 400.0;
pub const SPLIT_CHART_MAX_HEIGHT: f32 = 800.0;
// styling
pub const SPACE_BETWEEN_ELEMENTS: u16 = 10;
pub const SPACE_BETWEEN_TEXT: u16 = 3;
pub const APP_PADDING: u16 = 10;
pub const SPACE_BETWEEN_PLOT_ROWS: f32 = 10.0;
pub const HORIZONTAL_LINE_PRIMARY_HEIGHT: u16 = 10;
pub const HORIZONTAL_LINE_SECONDARY_HEIGHT: u16 = 5;
pub const SCROLLABLE_TEXT_WINDOWS_SIZE: u16 = 400;
