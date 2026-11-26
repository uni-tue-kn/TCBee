//! The TCBee logo in the run block, for terminals with a graphics protocol

use ratatui::layout::Rect;
use ratatui_image::{
    picker::{Picker, ProtocolType},
    protocol::Protocol,
    FilterType, Resize,
};

const LOGO_PNG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../docs/assets/tcbee-header.png"
));

/// Rows the logo spans: the lines of the run block
pub const LOGO_ROWS: u16 = 2;

/// The logo, sized once for the terminal's font
pub struct Logo {
    pub protocol: Protocol,
    /// Columns the logo spans
    pub cols: u16,
}

impl Logo {
    /// Asks the terminal for its graphics protocol. Run before the TUI captures the mouse and
    /// reads events, whose bytes would mix with the answer. None when the terminal only has
    /// half blocks, at which size the logo does not read, or when it does not answer.
    pub fn query() -> Option<Logo> {
        let picker = Picker::from_query_stdio().ok()?;
        if picker.protocol_type() == ProtocolType::Halfblocks {
            return None;
        }
        Logo::build(&picker)
    }

    /// The logo `LOGO_ROWS` high in the font of `picker`
    fn build(picker: &Picker) -> Option<Logo> {
        let image = image::load_from_memory_with_format(LOGO_PNG, image::ImageFormat::Png).ok()?;
        let cols = cols(picker.font_size(), image.width(), image.height());
        let area = Rect::new(0, 0, cols, LOGO_ROWS);
        let protocol = picker
            .new_protocol(image, area, Resize::Fit(Some(FilterType::Triangle)))
            .ok()?;
        Some(Logo { protocol, cols })
    }

    /// A logo of half blocks, which `query` never returns, for tests
    #[cfg(test)]
    pub fn for_test() -> Logo {
        Logo::build(&Picker::from_fontsize((8, 16))).unwrap()
    }
}

/// Columns an image of `width` x `height` pixels spans at `LOGO_ROWS` rows of `font` cells
fn cols((font_width, font_height): (u16, u16), width: u32, height: u32) -> u16 {
    let pixels_high = f64::from(LOGO_ROWS * font_height);
    let pixels_wide = pixels_high * f64::from(width) / f64::from(height.max(1));
    (pixels_wide / f64::from(font_width.max(1))).ceil() as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logo_spans_the_columns_of_its_aspect_ratio() {
        let logo = Logo::for_test();
        // 238x112 at 32 pixels high is 68 wide, 9 columns of 8 pixels
        assert_eq!(logo.cols, 9);
        assert_eq!(cols((10, 20), 200, 100), 8);
    }
}
