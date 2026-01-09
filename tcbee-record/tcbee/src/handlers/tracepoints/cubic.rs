use tcbee_common::bindings::cubic::cubic_trace_entry;

use crate::handlers::{BufferHandler, BufferHandlerImpl};

impl BufferHandlerImpl<cubic_trace_entry> for BufferHandler<cubic_trace_entry> {
    fn handle_event(&self, event: cubic_trace_entry) -> Option<cubic_trace_entry> {
        Some(event)
    }
}
