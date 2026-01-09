use tcbee_common::bindings::bbr::bbr_trace_entry;

use crate::handlers::{BufferHandler, BufferHandlerImpl};

impl BufferHandlerImpl<bbr_trace_entry> for BufferHandler<bbr_trace_entry> {
    fn handle_event(&self, event: bbr_trace_entry) -> Option<bbr_trace_entry> {
        Some(event)
    }
}
