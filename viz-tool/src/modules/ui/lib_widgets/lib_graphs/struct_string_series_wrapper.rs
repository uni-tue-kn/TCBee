// contains logic for Struct StringSeriesWrapper
//  used to combine and simplify usage of time-series that contain string values

use iced::{
    widget::{text, Column},
    Element,
};
use rust_ts_storage::DataValue;

use crate::modules::{
    backend::plot_data_preprocessing::extract_non_empty_string,
    ui::lib_styling::app_style_settings::SPACE_BETWEEN_TEXT,
};

#[derive(Debug, Clone)]
pub struct StringSeriesWrapper {
    pub name: String,

    pub formatted_collection: Vec<(f64, DataValue)>,
}

// explanation:
// lifetime set to be as long as Message is alive ( this in return can be set by the given generic type ( whenever its called ))
//  hence this is entirely dependant on the Message that was applied onto this implementation
pub fn view_wrapper<'a, Message: 'a>(to_convert: StringSeriesWrapper) -> Element<'a, Message> {
    let headline = text(format!("Values for {:?}", to_convert.name));
    let table_of_strings = display_collection_of_strings(&to_convert);

    let content = Column::new()
        .padding(SPACE_BETWEEN_TEXT)
        .push(headline)
        .push(table_of_strings);

    content.into()
}

pub fn display_collection_of_strings<'a, Message: 'a>(
    to_display: &StringSeriesWrapper,
) -> Element<'a, Message> {
    // let new_table = Table::
    let as_formatted_string: Vec<String> = to_display
        .formatted_collection
        .iter()
        .map(|collection| {
            let as_string = format!("{:?} | {:?} ", collection.0, collection.1);
            as_string
        })
        .collect();
    let mut column_of_strings = Column::new().padding(SPACE_BETWEEN_TEXT);

    for entry in as_formatted_string {
        column_of_strings = column_of_strings.push(text(entry))
    }

    column_of_strings.into()
}
