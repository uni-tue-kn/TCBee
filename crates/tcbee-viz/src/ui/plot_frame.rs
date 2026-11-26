//! Layout shared by the stacked plots of all tabs.

/// Minimum width of the y axis of stacked plots (px). The same in every plot of a stack,
/// so their time axes line up.
pub const Y_AXIS_WIDTH: f32 = 56.0;

/// Space between the left border and the title or legend of a plot (px).
pub const TITLE_INSET: f32 = 8.0;
/// Space above the title of a plot (px).
const TITLE_SPACE_ABOVE: f32 = 6.0;
/// Space between the title and its plot (px).
const TITLE_SPACE_BELOW: f32 = 2.0;
/// Height a plot title takes, without its text (px).
pub const TITLE_SPACING: f32 = TITLE_SPACE_ABOVE + TITLE_SPACE_BELOW;

/// The title above a plot, inset from the left border.
pub fn plot_title(ui: &mut egui::Ui, title: egui::RichText) {
    ui.add_space(TITLE_SPACE_ABOVE);
    ui.horizontal(|ui| {
        ui.add_space(TITLE_INSET);
        ui.label(title);
    });
    ui.add_space(TITLE_SPACE_BELOW);
}

/// Room below a plot stack for the time axis (px).
pub const PLOT_AXIS_FOOTER: f32 = 36.0;
/// Smallest height of a plot (px).
pub const MIN_PLOT_HEIGHT: f32 = 80.0;

/// Height of a plot title with the space around it (px).
pub fn title_height(ui: &egui::Ui) -> f32 {
    ui.text_style_height(&egui::TextStyle::Body) + TITLE_SPACING + 2.0 * ui.spacing().item_spacing.y
}

/// Height of the handle below a stacked plot that resizes it (px).
pub const RESIZE_HANDLE_HEIGHT: f32 = 6.0;

/// A stack of plots that fill the available height until the user drags one to a new
/// height. Then every plot keeps its height and the stack scrolls, until a reset.
pub struct PlotStack {
    /// Where the stack keeps the picked heights in the egui memory
    stack_id: egui::Id,
    ids: Vec<egui::Id>,
    heights: Vec<f32>,
    min: f32,
}

/// Heights picked by dragging, by plot id.
type PickedHeights = std::collections::HashMap<egui::Id, f32>;

impl PlotStack {
    /// The stack `stack_id` of the plots `ids` in `available` px, each below a title and
    /// above a resize handle. No plot gets less than `min`.
    pub fn new(
        ui: &egui::Ui,
        stack_id: egui::Id,
        ids: Vec<egui::Id>,
        available: f32,
        min: f32,
    ) -> Self {
        // The handle is one more item below the plot
        let per_plot = title_height(ui) + RESIZE_HANDLE_HEIGHT + ui.spacing().item_spacing.y;
        let room = available - PLOT_AXIS_FOOTER - ids.len() as f32 * per_plot;
        let picked_heights = picked(ui.ctx(), stack_id);
        let picked: Vec<Option<f32>> = picked_heights
            .map(|p| ids.iter().map(|id| p.get(id).copied()).collect())
            .unwrap_or_else(|| vec![None; ids.len()]);
        let heights = split_heights(room, &picked, min);
        Self {
            stack_id,
            ids,
            heights,
            min,
        }
    }

    /// Height of the plot at `index`.
    pub fn height(&self, index: usize) -> f32 {
        self.heights[index]
    }

    /// The handle below the plot at `index`. Dragging it resizes that plot only: on the
    /// first drag, every plot of the stack keeps its current height.
    pub fn resize_handle(&self, ui: &mut egui::Ui, index: usize) {
        let size = egui::vec2(ui.available_width(), RESIZE_HANDLE_HEIGHT);
        let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
        // A fixed id, so a drag survives a change of the layout around the handle
        let id = self.ids[index].with("resize_handle");
        let response = ui.interact(rect, id, egui::Sense::click_and_drag());
        if response.double_clicked() {
            reset_heights(ui.ctx(), self.stack_id);
        } else if response.dragged() || response.drag_started() {
            // Read outside data_mut: the delta takes the context lock too
            let delta = response.drag_delta().y;
            let start = response.drag_started();
            ui.data_mut(|d| {
                let picked = d.get_temp_mut_or_default::<PickedHeights>(self.stack_id);
                if start {
                    for (id, height) in self.ids.iter().zip(&self.heights) {
                        picked.entry(*id).or_insert(*height);
                    }
                }
                let height = picked.entry(self.ids[index]).or_insert(self.heights[index]);
                *height = (*height + delta).max(self.min);
            });
        }
        let response = response
            .on_hover_cursor(egui::CursorIcon::ResizeVertical)
            .on_hover_text("Drag to resize the plot, double-click to reset all");
        if response.hovered() || response.dragged() {
            let stroke = ui.visuals().widgets.hovered.fg_stroke;
            ui.painter().hline(rect.x_range(), rect.center().y, stroke);
        }
    }
}

fn picked(ctx: &egui::Context, stack_id: egui::Id) -> Option<PickedHeights> {
    ctx.data(|d| d.get_temp::<PickedHeights>(stack_id))
}

/// A plot of the stack `stack_id` was resized by hand.
pub fn heights_are_picked(ctx: &egui::Context, stack_id: egui::Id) -> bool {
    picked(ctx, stack_id).is_some_and(|p| !p.is_empty())
}

/// Back to plots that fill the available height.
pub fn reset_heights(ctx: &egui::Context, stack_id: egui::Id) {
    ctx.data_mut(|d| d.remove::<PickedHeights>(stack_id));
}

/// The heights of stacked plots: a picked height stays, the plots without one share the
/// rest of `total`. No plot gets less than `min`.
pub fn split_heights(total: f32, picked: &[Option<f32>], min: f32) -> Vec<f32> {
    let picked_sum: f32 = picked.iter().flatten().map(|h| h.max(min)).sum();
    let unpicked = picked.iter().filter(|h| h.is_none()).count().max(1);
    let share = ((total - picked_sum) / unpicked as f32).max(min);
    picked
        .iter()
        .map(|h| h.map_or(share, |h| h.max(min)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpicked_plots_share_what_the_picked_ones_leave() {
        assert_eq!(split_heights(300.0, &[None, None, None], 80.0), [100.0; 3]);
        assert_eq!(
            split_heights(300.0, &[Some(100.0), None, None], 80.0),
            [100.0, 100.0, 100.0]
        );
        assert_eq!(
            split_heights(400.0, &[Some(80.0), None], 80.0),
            [80.0, 320.0]
        );
    }

    #[test]
    fn an_empty_stack_has_no_heights() {
        assert!(split_heights(300.0, &[], 80.0).is_empty());
    }

    #[test]
    fn no_plot_gets_less_than_the_minimum() {
        assert_eq!(
            split_heights(100.0, &[Some(90.0), None, None], 80.0),
            [90.0, 80.0, 80.0]
        );
        assert_eq!(
            split_heights(300.0, &[Some(10.0), Some(500.0), None], 80.0),
            [80.0, 500.0, 80.0]
        );
    }
}
