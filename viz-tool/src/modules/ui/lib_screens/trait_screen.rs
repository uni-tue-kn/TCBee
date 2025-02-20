// contains small pre-made functions to simplify visualizations with ICED

use std::sync::RwLock;

// -- external imports
use iced::widget::{radio, Column, Container};
use iced::{Color, Element, Length};
use iced_aw::TabLabel;

use crate::modules::backend::app_settings::ApplicationSettings;
// -- internal imports
use crate::{Arc, Message};

pub trait Screen {
    type Message;

    fn receive_settings(&self) -> &Arc<RwLock<ApplicationSettings>>;

    fn title(&self) -> String;

    fn content(&self) -> Element<'_, Self::Message>;

    fn tab_label(&self) -> TabLabel;

    fn view(&self) -> Element<'_, Self::Message> {
        // defining which screen to "display"
        // could be used to dynamically change the content displayed
        let displayed_screen = self.content();
        // collecting both values --> column so they are aligned vertically
        Container::new(displayed_screen)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
        // .max_width(400)
    }

}
