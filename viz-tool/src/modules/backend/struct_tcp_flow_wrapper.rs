// module containing logic used to represent a TCP flow
//  features:
//  Flow-Id
//  Flow-Series
//
//  addtitional methods to update and modify this struct are implemented as well

#[derive(Clone, Debug)]
pub struct TcpFlowWrapper {
    pub flow_id: Option<i64>,
    pub selected_series: Option<Vec<i64>>,
}

impl TcpFlowWrapper {
    pub fn series_id_is_selected(&self, id_to_check: &i64) -> bool {
        match &self.selected_series {
            Some(vec_of_ids) => {
                for id in vec_of_ids {
                    if id.eq(id_to_check) {
                        return true;
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// takes ID and adds it to the vector of time series ids
    ///
    /// INVARIANT: assumes that no ID can be added twice --> its conceptualized as set!
    pub fn add_new_series(&mut self, attribute_id: i64) {
        match &mut self.selected_series.as_ref() {
            Some(vec_of_ids) => {
                // FIXME improve readability!
                let mut old_vec = vec_of_ids.clone();
                old_vec.push(attribute_id);
                self.selected_series = Some(old_vec)
            }
            None => {
                //  creating new vector
                self.selected_series = Some(Vec::from([attribute_id]))
            }
        }
    }

    pub fn remove_series(&mut self, attribute_id: &i64) {
        if let Some(vec_of_ids) = &mut self.selected_series {
            // found valid set of entries
            let old_vec = vec_of_ids.clone();
            let new_vec: Vec<i64> = old_vec
                .into_iter()
                .filter(|id| !id.eq(attribute_id))
                .collect();
            if new_vec.is_empty() {
                self.selected_series = None
            } else {
                self.selected_series = Some(new_vec);
            }
        }
    }
}

impl Default for TcpFlowWrapper {
    fn default() -> Self {
        TcpFlowWrapper {
            flow_id: None,
            selected_series: None,
        }
    }
}
