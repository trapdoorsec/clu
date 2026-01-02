use crate::output::{AnalysisReport, Formatter};

pub struct ColouredTextFormatter {}

impl Formatter for ColouredTextFormatter {
    fn format_report(&self, report: &AnalysisReport) -> String {
        todo!()
    }
}