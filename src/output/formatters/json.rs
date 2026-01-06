#![allow(dead_code)]

use crate::output::AnalysisReport;
use crate::output::Formatter;

pub struct JsonFormatter;
impl Formatter for JsonFormatter {
    fn format_report(&self, report: &AnalysisReport) -> String {
        serde_json::to_string_pretty(report).unwrap()
    }
}