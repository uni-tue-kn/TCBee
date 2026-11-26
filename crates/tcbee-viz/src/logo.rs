//! The TCBee logo, embedded from docs/assets

const HEADER_PNG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/assets/tcbee-header.png"
));
const ICON_PNG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/assets/tcbee-icon.png"
));

/// The bee alone, for the window and taskbar icon
pub fn icon() -> Option<egui::IconData> {
    eframe::icon_data::from_png_bytes(ICON_PNG)
        .inspect_err(|err| eprintln!("tcbee-viz: cannot decode the window icon: {err}"))
        .ok()
}

/// The full logo as a texture for the top bar
pub fn header(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let data = eframe::icon_data::from_png_bytes(HEADER_PNG)
        .inspect_err(|err| eprintln!("tcbee-viz: cannot decode the logo: {err}"))
        .ok()?;
    let size = [data.width as usize, data.height as usize];
    let image = egui::ColorImage::from_rgba_unmultiplied(size, &data.rgba);
    Some(ctx.load_texture("tcbee-logo", image, egui::TextureOptions::LINEAR))
}

#[cfg(test)]
mod tests {
    #[test]
    fn embedded_images_decode() {
        let header = eframe::icon_data::from_png_bytes(super::HEADER_PNG).unwrap();
        assert!(header.width > header.height, "the logo is wide");
        let icon = eframe::icon_data::from_png_bytes(super::ICON_PNG).unwrap();
        assert_eq!(icon.width, icon.height, "the icon is square");
    }
}
