use egui::{Color32, FontFamily, FontId, Stroke, TextStyle};

pub const APP_BG: Color32 = Color32::from_rgb(245, 247, 250);
pub const PANEL_BG: Color32 = Color32::from_rgb(255, 255, 255);
pub const SIDEBAR_BG: Color32 = Color32::from_rgb(249, 250, 252);
pub const TOP_BAR_BG: Color32 = Color32::from_rgb(19, 26, 38);
pub const TOP_BAR_ACTIVE: Color32 = Color32::from_rgb(37, 99, 235);
pub const TOP_BAR_TEXT: Color32 = Color32::from_rgb(226, 232, 240);
pub const TEXT: Color32 = Color32::from_rgb(24, 33, 47);
pub const MUTED_TEXT: Color32 = Color32::from_rgb(100, 116, 139);
pub const BORDER: Color32 = Color32::from_rgb(218, 226, 236);
pub const TABLE_HEADER_BG: Color32 = Color32::from_rgb(229, 237, 247);
pub const TABLE_HEADER_TEXT: Color32 = Color32::from_rgb(51, 65, 85);
pub const TABLE_ROW_ODD: Color32 = Color32::from_rgb(244, 248, 253);
pub const TABLE_ROW_EVEN: Color32 = Color32::from_rgb(250, 252, 255);
pub const TABLE_ROW_HOVER: Color32 = Color32::from_rgb(234, 241, 251);
pub const TABLE_ROW_SELECTED: Color32 = Color32::from_rgb(219, 234, 254);
pub const TABLE_ROW_SELECTED_HOVER: Color32 = Color32::from_rgb(191, 219, 254);
pub const SUCCESS: Color32 = Color32::from_rgb(22, 163, 74);
pub const ERROR: Color32 = Color32::from_rgb(220, 38, 38);

pub fn app_bg(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(13, 18, 27)
    } else {
        APP_BG
    }
}

pub fn panel_bg(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(20, 27, 39)
    } else {
        PANEL_BG
    }
}

pub fn sidebar_bg(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(16, 22, 33)
    } else {
        SIDEBAR_BG
    }
}

pub fn text(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(226, 232, 240)
    } else {
        TEXT
    }
}

pub fn muted_text(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(148, 163, 184)
    } else {
        MUTED_TEXT
    }
}

pub fn border(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(51, 65, 85)
    } else {
        BORDER
    }
}

pub fn table_header_bg(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(35, 48, 68)
    } else {
        TABLE_HEADER_BG
    }
}

pub fn table_header_text(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(203, 213, 225)
    } else {
        TABLE_HEADER_TEXT
    }
}

pub fn table_row_odd(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(19, 28, 42)
    } else {
        TABLE_ROW_ODD
    }
}

pub fn table_row_even(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(23, 32, 47)
    } else {
        TABLE_ROW_EVEN
    }
}

pub fn table_row_hover(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(31, 44, 64)
    } else {
        TABLE_ROW_HOVER
    }
}

pub fn table_row_selected(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(30, 58, 95)
    } else {
        TABLE_ROW_SELECTED
    }
}

pub fn table_row_selected_hover(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(37, 72, 118)
    } else {
        TABLE_ROW_SELECTED_HOVER
    }
}

pub fn apply(ctx: &egui::Context, dark_mode: bool, text_size: f32) {
    let mut visuals = if dark_mode {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    visuals.window_fill = app_bg(dark_mode);
    visuals.panel_fill = app_bg(dark_mode);
    visuals.extreme_bg_color = panel_bg(dark_mode);
    visuals.faint_bg_color = if dark_mode {
        Color32::from_rgb(24, 33, 47)
    } else {
        Color32::from_rgb(241, 245, 249)
    };
    visuals.code_bg_color = if dark_mode {
        Color32::from_rgb(30, 41, 59)
    } else {
        Color32::from_rgb(236, 242, 248)
    };
    visuals.selection.bg_fill = if dark_mode {
        Color32::from_rgb(30, 64, 115)
    } else {
        Color32::from_rgb(191, 219, 254)
    };
    visuals.selection.stroke = Stroke::new(1.0, TOP_BAR_ACTIVE);
    visuals.hyperlink_color = TOP_BAR_ACTIVE;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, border(dark_mode));
    visuals.widgets.inactive.bg_fill = if dark_mode {
        panel_bg(dark_mode)
    } else {
        Color32::from_rgb(232, 239, 248)
    };
    visuals.widgets.inactive.weak_bg_fill = if dark_mode {
        Color32::from_rgb(30, 41, 59)
    } else {
        Color32::from_rgb(241, 245, 251)
    };
    visuals.widgets.inactive.bg_stroke = Stroke::new(
        1.25,
        if dark_mode {
            border(dark_mode)
        } else {
            Color32::from_rgb(154, 170, 191)
        },
    );
    visuals.widgets.inactive.fg_stroke = Stroke::new(
        1.5,
        if dark_mode {
            Color32::from_rgb(203, 213, 225)
        } else {
            Color32::from_rgb(71, 85, 105)
        },
    );
    visuals.widgets.hovered.bg_fill = if dark_mode {
        Color32::from_rgb(30, 41, 59)
    } else {
        Color32::from_rgb(224, 235, 249)
    };
    visuals.widgets.hovered.bg_stroke = Stroke::new(
        1.25,
        if dark_mode {
            border(dark_mode)
        } else {
            Color32::from_rgb(96, 125, 164)
        },
    );
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.5, TOP_BAR_ACTIVE);
    visuals.widgets.active.bg_fill = if dark_mode {
        Color32::from_rgb(36, 55, 86)
    } else {
        Color32::from_rgb(214, 229, 249)
    };
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, TOP_BAR_ACTIVE);
    visuals.widgets.active.fg_stroke = Stroke::new(1.75, TOP_BAR_ACTIVE);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 7.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    style.spacing.interact_size = egui::vec2(40.0, 26.0);
    style.spacing.slider_width = 220.0;
    style.spacing.text_edit_width = 220.0;
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new((text_size + 6.0).min(24.0), FontFamily::Proportional),
    );
    style
        .text_styles
        .values_mut()
        .for_each(|font| font.size = font.size.min(text_size + 6.0).max(text_size));
    style.text_styles.insert(
        TextStyle::Body,
        FontId::new(text_size, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(text_size, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new((text_size - 1.0).max(10.0), FontFamily::Proportional),
    );
    ctx.set_style(style);
}

pub fn sidebar_frame(dark_mode: bool) -> egui::Frame {
    egui::Frame::new()
        .fill(sidebar_bg(dark_mode))
        .inner_margin(egui::Margin::symmetric(0, 10))
        .stroke(Stroke::new(1.0, border(dark_mode)))
}
