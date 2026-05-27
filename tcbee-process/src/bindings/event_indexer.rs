use ts_storage::{DataValue, IpTuple};

// TODO: There should be a way to implement this with macros, derive crate
pub trait EventIndexer {
    // First filed is always timestamp, second is address
    fn get_field(&self, index: usize) -> DataValue;
    fn get_default_field(&self, index: usize) -> DataValue;
    fn get_field_name(&self, index: usize) -> &str;
    fn get_ip_tuple(&self) -> IpTuple;
    fn get_max_index(&self) -> usize;
    fn get_timestamp(&self) -> f64;
    fn get_struct_length(&self) -> usize;
    fn check_divider(&self) -> bool;
}
