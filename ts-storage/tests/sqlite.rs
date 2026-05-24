use ts_storage::{
    database_factory, DBBackend, DataPoint, DataValue, FlowAttribute, IpTuple, TSDBInterface,
};
use std::net::IpAddr;
use std::str::FromStr;

#[test]
fn all_func() {
    let db: Box<dyn TSDBInterface + Send> =
        database_factory(DBBackend::SQLite("db_sqlite_test.sqlite".to_owned()))
            .expect("Failed to open database!");

    let testuple = IpTuple {
        src: IpAddr::from_str("10.0.0.1").unwrap(),
        dst: IpAddr::from_str("10.0.0.2").unwrap(),
        sport: 100,
        dport: 200,
        l4proto: 16,
    };

    // ---- Create, list and delete a flow
    let flow = db.create_flow(&testuple).expect("Failed to write flow!");
    let list = db.list_flows().expect("Failed to get flows!");
    for entry in list {
        println!("Entry: {entry:?}")
    }
    let _ = db.delete_flow(&flow).expect("Failed to delete flow!");

    // -- Create, list and delete flow attribute
    let flow2 = db.create_flow(&testuple).expect("Failed to write flow!");
    let mut list = db.list_flows().expect("Failed to get flows!");
    let _ = list.next().unwrap();

    let mut attr = FlowAttribute {
        name: "TEST".to_string(),
        value: DataValue::String("TEST".to_string()),
    };

    let _ = db.add_flow_attribute(&flow2, &attr).expect("Failed to add flow attribute!");

    attr.value = DataValue::Int(100);
    let _ = db.set_flow_attribute(&flow2, &attr).expect("Cannot update attribute!");

    let attr_res = db.get_flow_attribute(&flow2, "TEST").expect("Cannot get flow attribute!");
    println!("Attribute: {attr_res:?}");

    let attr2 = FlowAttribute {
        name: "TEST2".to_string(),
        value: DataValue::String("TEST".to_string()),
    };
    let _ = db.add_flow_attribute(&flow2, &attr2).expect("Failed to add second flow attribute!");

    let attr_list = db.list_flow_attributes(&flow2).expect("Could not get FlowAttribute list!");
    for entry in attr_list {
        println!("Attribute List: {entry:?}");
    }

    let _ = db.delete_flow_attribute(&flow2, "TEST").expect("Could not delete first attribute!");
    let _ = db.delete_flow_attribute(&flow2, "TEST2").expect("Could not delete second attribute!");
    let _ = db.delete_flow(&flow2).expect("Failed to delete flow!");

    // -- Create, list and delete time series for flow
    let flow3 = db.create_flow(&testuple).expect("Failed to write flow!");
    let mut list = db.list_flows().expect("Failed to get flows!");
    let selected_flow = list.next().unwrap();
    println!("Selected Flow: {selected_flow:?}");

    let ts1 = db
        .create_time_series(&flow3, "TestTS", DataValue::Int(0))
        .expect("Failed to create TS");

    let ts_list = db.list_time_series(&flow3).expect("Failed to list TS");
    for ts in ts_list {
        println!("TS: {ts:?}")
    }

    let entry = DataPoint { timestamp: 0.0, value: DataValue::Int(10) };
    let vec_entry = vec![
        DataPoint { timestamp: 0.5, value: DataValue::Int(10) },
        DataPoint { timestamp: 1.0, value: DataValue::Int(11) },
        DataPoint { timestamp: 2.0, value: DataValue::Int(12) },
        DataPoint { timestamp: 3.0, value: DataValue::Int(13) },
    ];

    let _ = db.insert_data_point(&ts1, &entry);
    let _ = db.insert_multiple_points(&ts1, &vec_entry).expect("Failed to add points from vector!");

    let wrong_entries = vec![
        DataPoint { timestamp: 99.0, value: DataValue::Int(1) },
        DataPoint { timestamp: 99.0, value: DataValue::Int(2) },
    ];
    let res = db.insert_multiple_points(&ts1, &wrong_entries);
    println!("See: {res:?}");
    if res.is_err() {
        println!("Failed write!")
    }

    let right_entries = vec![
        DataPoint { timestamp: 99.0, value: DataValue::Int(3) },
        DataPoint { timestamp: 100.0, value: DataValue::Int(4) },
    ];
    let _ = db.insert_multiple_points(&ts1, &right_entries).expect("Transaction rollback failed!");

    let bounds = db.get_time_series_bounds(&ts1).expect("Failed to get bounds!");
    println!("Bounds: {bounds:?}");

    let num = db.get_data_points_count(&ts1).expect("Failed to get data point count!");
    println!("Number of entries: {num:?}");

    let flow_bounds = db.get_flow_bounds(&flow3).expect("Failed to get flow bounds");
    println!("Flow bounds: {flow_bounds:?}");

    // Test range filter
    let range_points = db
        .get_data_points_in_range(&ts1, 0.5, 2.0)
        .expect("Failed to get data points in range");
    println!("Range points (0.5..2.0):");
    for p in range_points {
        println!("  Point: {p:?}")
    }

    let points = db.get_data_points(&ts1).expect("Failed to get data points");
    for p in points {
        println!("Point: {p:?}")
    }
}
