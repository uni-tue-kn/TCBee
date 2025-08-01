//  contains logic for widgets useable in this application
//  primarily contains widgets used in:
//  - Sidebars
//  - App-Settings
//  ...

use std::sync::{Arc, RwLock};

use crate::{modules::{
    backend::{
        app_settings::ApplicationSettings, intermediate_backend::IntermediateBackend, lib_system_io::receive_file_metadata, plot_data_preprocessing::convert_rgba_to_iced_color, struct_tcp_flow_wrapper::TcpFlowWrapper
    },
    ui::{
        lib_styling::app_style_settings::{
            HORIZONTAL_LINE_PRIMARY_HEIGHT, HORIZONTAL_LINE_SECONDARY_HEIGHT, PADDING_AROUND_CONTENT, SLIDER_STEP_SIZE, SPACE_BETWEEN_ELEMENTS, SPLIT_CHART_MAX_HEIGHT, SPLIT_CHART_MIN_HEIGHT, TEXT_HEADLINE_0_SIZE, TEXT_HEADLINE_1_SIZE, TEXT_HEADLINE_2_SIZE
        },
        lib_widgets::lib_graphs::{
            struct_processed_plot_data::ProcessedPlotData,
            struct_string_series_wrapper::{view_wrapper, StringSeriesWrapper},
            struct_zoom_bounds::ZoomBound2D,
        },
    },
}, Message};
use iced::{
    theme::palette::Background, widget::{
        button, checkbox, radio, scrollable, slider, text, Button, Checkbox, Column, Row, Rule,
        Space, Text,
    }, Alignment, Element, Length
};

/// OTHER FUNCTIONS
pub fn display_current_mouse_position<'a, Message: 'a>(
    maybe_position: Option<(f64, f64)>,
) -> Column<'a, Message> {
    let headline = text("Currently hovered position:").size(TEXT_HEADLINE_1_SIZE);
    let position_text = match maybe_position {
        Some(values) => {
            format!("x:{:?}, y:{:?}", values.0, values.1)
        }
        _ => format!("No position hovered"),
    };
    let new_content = Column::new()
        .spacing(SPACE_BETWEEN_ELEMENTS)
        .push(headline)
        .push(text(position_text));
    // .into();
    new_content
}

pub fn display_flow_selector<'a, Message: 'a + Clone>(
    ref_backend: &IntermediateBackend,
    focused_flow: &TcpFlowWrapper,
    message_on_click: impl Fn(i64) -> Message + 'a + Clone,
) -> Column<'a, Message> {
    let headline = text("Flow Selection:").size(TEXT_HEADLINE_1_SIZE);
    let description = text("select a flow to observe and analyse");
    let collection_of_flows =
        generate_selections_for_flows(ref_backend, &focused_flow, message_on_click);

    Column::new()
        .spacing(SPACE_BETWEEN_ELEMENTS)
        .push(headline)
        .push(description)
        .push(Space::with_height(HORIZONTAL_LINE_SECONDARY_HEIGHT))
        .push(scrollable(collection_of_flows))
    // .into()
}

fn generate_selections_for_flows<'a, Message: 'a + Clone>(
    ref_backend: &IntermediateBackend,
    focused_flow: &TcpFlowWrapper,
    message_on_click: impl Fn(i64) -> Message + 'a + Clone,
) -> Column<'a, Message> {
    let mut new_col: Column<'a, Message> = Column::new();
    let interface = &ref_backend.database_interface;

    if let Some(db_connection) = interface {

        let header_1: Row<'_, _> = Row::<Message>::new()
            .push(Text::new("ID").width(Length::FillPortion(1))) // Space for radio button
            .push(Text::new("Source").width(Length::FillPortion(3)))
            .push(Text::new("Destination").width(Length::FillPortion(3)));


        new_col = new_col.push(header_1);

        let all_flows = db_connection.list_flows().expect("could not find flows");
        for entry in all_flows {

            let tuple = &entry.tuple;
            let first_flow_row = Row::<Message>::new()
                .push(Text::new(entry.get_id().unwrap()).width(Length::FillPortion(1)))
                .push(Text::new(tuple.src.to_string()).width(Length::FillPortion(3)))
                .push(Text::new(tuple.dst.to_string()).width(Length::FillPortion(3)));
            let second_flow_row = Row::<Message>::new()
                .push(
                    radio(
                    "",
                    entry.get_id().expect("no flow id"),
                    focused_flow.flow_id,
                    message_on_click.clone(),
                    ) 
                    .width(Length::FillPortion(1))
                )
                .push(Text::new(tuple.sport.to_string()).width(Length::FillPortion(3)))
                .push(Text::new(tuple.dport.to_string()).width(Length::FillPortion(3)));
                

            new_col = new_col.push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT)).push(first_flow_row).push(second_flow_row);
        }
    }
    new_col
}

pub fn display_series_selector<'a, Message: 'a + Clone>(
    ref_backend: &IntermediateBackend,
    message_on_select: impl Fn(i64) -> Message + 'a + Clone,
    message_on_deselect: impl Fn(i64) -> Message + 'a + Clone,
    message_on_unselect_all: Message,
    focused_flow: &TcpFlowWrapper,
) -> Element<'a, Message> {
    let headline = text("Series Selection:").size(TEXT_HEADLINE_1_SIZE);
    let description = text("select one or more attributes to display");
    let maybe_collection_of_series = generate_selections_for_series_data(
        ref_backend,
        message_on_select,
        message_on_deselect,
        message_on_unselect_all,
        focused_flow,
    );
    let widget_collection: Element<'_, Message>= match maybe_collection_of_series{
        Ok(widget) => widget.into(),
        Err(string) => text(string).into()
    };
    Column::new()
        .spacing(SPACE_BETWEEN_ELEMENTS)
        .push(headline)
        .push(description)
        .push(Space::with_height(HORIZONTAL_LINE_SECONDARY_HEIGHT))
        .push(widget_collection)
        .into()
}

// FIXME update to request from implementing Screen instead!
fn generate_selections_for_series_data<'a, Message: 'a + Clone>(
    ref_backend: &IntermediateBackend,
    message_on_select: impl Fn(i64) -> Message + 'a + Clone,
    message_on_deselect: impl Fn(i64) -> Message + 'a + Clone,
    message_on_unselect_all: Message,
    screen_flow: &TcpFlowWrapper,
) -> Result<Column<'a, Message>,String> {
    let mut column: Column<'a, Message> = Column::new();

    column  = column.push(
        generate_series_unselect_button(message_on_unselect_all)
    );

    let database_connection  = &ref_backend.database_interface.clone().expect("No database connection found");

        //  found connection, attempting to read from it
        let maybe_selected_flow = &ref_backend
            .receive_selected_flow(screen_flow.flow_id);
        let flow = match maybe_selected_flow {
            Some(flow) => flow,
            _ => return Err("no active flow found, although its not none".to_string())
        };

        let maybe_avail_time_series = database_connection
            .list_time_series(flow);
        let available_time_series = match maybe_avail_time_series{
            Ok(time_series) => time_series,
            _ => return Err("could not retrieve time series for flow, non available".to_string())
        };
        for time_series in available_time_series {
            // FIXME necessary to unwrap correctly?
            let is_selected: bool =
                screen_flow.series_id_is_selected(&time_series.id.expect("no id found for flow"));

            // reasonable to copy closure here?
            let copy_of_message_select = message_on_select.clone();
            let copy_of_message_deselect = message_on_deselect.clone();
            //  creating checkbox for each flow
            let new_checkbox: Checkbox<'a, Message> = checkbox(
                format!(
                    "{:?} of type: {:?}",
                    &time_series.name,
                    time_series.ts_type.type_as_string()
                ),
                is_selected,
            )
            .on_toggle(move |state| {
                if !state {
                    // we know it was selected
                    println!("de selecting value: {:?}", time_series.name);
                    copy_of_message_deselect(time_series.id.unwrap())
                } else {
                    println!("selecting value: {:?}", time_series.name);
                    copy_of_message_select(time_series.id.unwrap())
                }
            });
            // .on_toggle(MessagePlotting::FlowFeatureSelected);
            column = column.push(new_checkbox);
        }
    return Ok(column);
}


pub fn generate_render_button<'a, Message: 'a + Clone>(
    message_on_press: Message,
) -> Element<'a, Message> {
    let render_button: Button<'a, Message> = button("press to render").on_press(message_on_press);
    render_button.into()
}
pub fn generate_series_unselect_button<'a, Message: 'a + Clone>(
    message_on_press: Message,
) -> Element<'a, Message> {
    let render_button: Button<'a, Message> = button("unselet all series").on_press(message_on_press);
    render_button.into()
}
pub fn generate_zoom_reset_button<'a, Message: 'a + Clone>(
    message_on_press: Message,
) -> Element<'a, Message> {
    button("reset zoom").on_press(message_on_press).into()
}
pub fn display_split_graph_selector<'a, Message: 'a + Clone>(
    state: bool,
    message_on_toggle: impl Fn(bool) -> Message + 'a + Clone,
) -> Element<'a, Message> {
    let checkbox_split = checkbox("Split Graphs", state).on_toggle(message_on_toggle);
    Column::new()
        .push(text(
            "either render everything in one chart, or multiple ones",
        ))
        .push(checkbox_split)
        .into()
}

pub fn display_line_series_toggle<'a, Message: 'a + Clone>(
    state: bool,
    message_on_toggle: impl Fn(bool) -> Message + 'a + Clone,
) -> Element<'a, Message> {
    let checkbox_series =
        checkbox("Display With Individual Points", state).on_toggle(message_on_toggle);
    Column::new()
        .push(text(
            "either render everything in one chart, or multiple ones",
        ))
        .push(checkbox_series)
        .into()
}
/// returns formatted information about selected database
/// if no database was given, nothing is returned
pub fn display_database_metadata<'a, Message: 'a + Clone>(
    app_settings_arc: &Arc<RwLock<ApplicationSettings>>,
) -> Element<'a, Message> {
    let read_settings = app_settings_arc.read().unwrap();
    let maybe_path = &read_settings.intermediate_interface.database_path;
    let maybe_db_info =match maybe_path {
        Some(path) => {
            receive_file_metadata(path)
        }
        _ => { 
            "No information could be obtained about database.".to_string()
        }
    };

    let headline = text("Information About Database:").size(TEXT_HEADLINE_1_SIZE);
    let description = text("listing information about database");
    let db_name = text(format!("selected database: {:?}", read_settings.datasource));
    let db_path = text(format!("path: {:?}", maybe_path));
    let db_metadata = text(maybe_db_info);
    Column::new()
        .push(headline)
        .push(description)
        .push(Space::with_height(HORIZONTAL_LINE_SECONDARY_HEIGHT))
        .push(db_name)
        .push(db_path)
        .push(db_metadata)
        .into()
}

pub fn display_zoom_instructions<'a, Message: 'a>(split_charts: &bool) -> Element<'a, Message> {
    let headline = text("Zoom Usage:").size(TEXT_HEADLINE_1_SIZE);
    let description = text("Into The Graph\n Select an area with a Left-Click on the Graph\nReset the Zoom either by pressing the Button or Right-Clicking");
    let description_split_chart = text("Zooming is unavailable for Split-Graphs, However:\nThe Graph will be zoomed in accordingly for a given selection.\nThe range of timestamps to Display can be adjusted");
    // lifetime of column is given by this methods call as well
    let new_column = Column::new()
        .spacing(SPACE_BETWEEN_ELEMENTS)
        .push(headline)
        .push(description)
        .push(match split_charts {
            true => description_split_chart,
            false => text(""),
        });

    new_column.into()
}

pub fn display_zoom_sliders<'a, Message: 'a + Clone>(
    app_settings_arc: &Arc<RwLock<ApplicationSettings>>,
    message_on_slider_left: impl Fn(f64) -> Message + 'a + Clone,
    message_on_slider_right: impl Fn(f64) -> Message + 'a + Clone,
    current_zoom_bounds: &Option<ZoomBound2D>,
    focused_flow: &TcpFlowWrapper,
) -> Column<'a, Message> {
    let read_settings = app_settings_arc.read().unwrap();
    // it can invoke the correct lifetime given the upper lifetime of this call
    let new_column: Column<'_, Message> = Column::new();

    let maybe_flow_x_zoom_bound = read_settings
        .intermediate_interface
        .receive_active_flow_bounds_x(&focused_flow.flow_id);

    if maybe_flow_x_zoom_bound.is_none() {
        return new_column;
    }

    let flow_x_zoom_bound = maybe_flow_x_zoom_bound.expect("no flow found");

    let current_zoom = current_zoom_bounds.clone().unwrap_or_default();

    let headline = text("Change Range To Visualize").size(TEXT_HEADLINE_1_SIZE);
    let description = text("limit the selection of timestamps to visualize");
    let lower_headline = text("Lower Bound:").size(TEXT_HEADLINE_2_SIZE);
    let upper_headline = text("Upper Bound:").size(TEXT_HEADLINE_2_SIZE);
    let lower_slider = slider(
        flow_x_zoom_bound.lower..=flow_x_zoom_bound.upper,
        current_zoom.x.lower,
        message_on_slider_left,
    )
    .step(SLIDER_STEP_SIZE);
    let lower_current_selection = text(format!(
        "{:?} <--> {:?}\ncurrently:{:?}",
        flow_x_zoom_bound.lower, flow_x_zoom_bound.upper, current_zoom.x.lower
    ));

    let upper_slider = slider(
        current_zoom.x.lower..=flow_x_zoom_bound.upper,
        current_zoom.x.upper,
        message_on_slider_right,
    )
    .step(SLIDER_STEP_SIZE);
    let upper_current_selection = text(format!(
        "{:?} <--> {:?}\ncurrently:{:?}",
        current_zoom.x.lower, flow_x_zoom_bound.upper, current_zoom.x.upper
    ));

    let new_column = Column::new()
        .spacing(10)
        .push(headline)
        .push(description)
        .push(lower_headline)
        .push(lower_current_selection)
        .push(lower_slider)
        .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT))
        .push(upper_headline)
        .push(upper_current_selection)
        .push(upper_slider);

    return new_column;
}

pub fn display_combined_flow_selection<'a, Message: 'a + Clone>(
    headline: String,
    intermediate_backend: &IntermediateBackend,
    flow_information: &TcpFlowWrapper,
    message_on_flow_selection: impl Fn(i64) -> Message + 'a + Clone,
    message_on_series_selection: impl Fn(i64) -> Message + 'a + Clone,
    message_on_series_deselection: impl Fn(i64) -> Message + 'a + Clone,
    message_on_unselect_all: Message,
) -> Column<'a, Message> {
    let headline = text(headline).size(TEXT_HEADLINE_0_SIZE);

    let flow_selector = display_flow_selector(
        &intermediate_backend,
        flow_information,
        message_on_flow_selection,
    );

    let series_selector = display_series_selector(
        &intermediate_backend,
        message_on_series_selection,
        message_on_series_deselection,
        message_on_unselect_all,
        flow_information,
    );
    let content: Column<'_, Message> = Column::new()
        .spacing(SPACE_BETWEEN_ELEMENTS)
        .push(headline)
        .push(flow_selector)
        .push(Rule::horizontal(HORIZONTAL_LINE_SECONDARY_HEIGHT))
        .push(series_selector);

    content
}

pub fn display_combined_flow_buttons<'a, Message: 'a + Clone>(
    message_on_render_graph: Message,
    message_on_zoom_reset: Message,
    display_zoom_reset: bool,
) -> Column<'a, Message> {
    let content = match display_zoom_reset {
        true => Column::new()
            .spacing(SPACE_BETWEEN_ELEMENTS)
            .push(generate_render_button(message_on_render_graph))
            .push(generate_zoom_reset_button(message_on_zoom_reset)),
        false => Column::new()
            .spacing(SPACE_BETWEEN_ELEMENTS)
            .push(generate_render_button(message_on_render_graph)),
    };

    content
}

pub fn display_split_graph_height_slider<'a, Message: 'a + Clone>(
    message_on_slider_change: impl Fn(f32) -> Message + 'a + Clone,
    current_split_height: &f32,
    is_split: &bool,
) -> Element<'a, Message> {
    let headline = text("Graph-Box Height:").size(TEXT_HEADLINE_1_SIZE);
    let description = text("adjust the size of the plot-windows for Split-Graph");
    let current_size = text(format!("current Size:{:?}", current_split_height));
    let size_slider = slider(
        SPLIT_CHART_MIN_HEIGHT..=SPLIT_CHART_MAX_HEIGHT,
        current_split_height.clone(),
        message_on_slider_change,
    );

    match is_split {
        true => Column::new()
            .spacing(SPACE_BETWEEN_ELEMENTS)
            .push(headline)
            .push(description)
            .push(current_size)
            .push(size_slider)
            .into(),
        false => Column::new().into(),
    }
}

pub fn display_empty_screen_no_data<'a, Message: 'a + Clone>() -> Element<'a, Message> {
    let content = Column::new()
        .width(Length::Fill)
        .height(Length::Fill)
        .push(text("No Database Available").size(TEXT_HEADLINE_0_SIZE))
        .align_x(Alignment::Center);
    content.into()
}

pub fn generate_legends_for_charts<'a, Message: 'a>(
    display_legends: bool,
    plot_data_ref: &Option<ProcessedPlotData>,
) -> Element<'a, Message> {
    let mut legend_column: Column<'a, Message> = Column::new();
    if !display_legends {
        return legend_column.into();
    }
    if let Some(plot_data) = &plot_data_ref {
        legend_column = legend_column.push(text("Graph Legends:").size(TEXT_HEADLINE_1_SIZE));
        //  generating legends to visualize colors
        for series in &plot_data.point_collection {
            let graph_legend = Row::new().push(
                text(format!("{:?}", series.name))
                    .color(convert_rgba_to_iced_color(&series.line_color)),
            );
            legend_column = legend_column.push(graph_legend);
        }
        legend_column.into()
    } else {
        legend_column.into()
    }
}

pub fn generate_padded_layout<'a, Message: 'a>(padding_value:u16) -> Column<'a, Message> {
    let window_content: Column<'a, Message> = Column::new()
        .padding(padding_value)
        .spacing(SPACE_BETWEEN_ELEMENTS);
    window_content
}

pub fn display_prepared_string<'a, Message: 'a>(
    wrapper_collection: Vec<StringSeriesWrapper>,
) -> Element<'a, Message> {
    let raw_iter: std::vec::IntoIter<StringSeriesWrapper> = wrapper_collection.into_iter();
    let content: Column<'a, Message> = raw_iter.fold(
        Column::new(),
        |mut column: Column<'a, Message>, wrapper: StringSeriesWrapper| {
            column = column.push(view_wrapper(wrapper));
            column
        },
    );
    content.into()
}
