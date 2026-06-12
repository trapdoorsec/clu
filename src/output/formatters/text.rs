#![allow(dead_code)]

use crate::output::AnalysisReport;
use crate::output::Formatter;

pub struct TextFormatter {}

impl Formatter for TextFormatter {
    fn format_report(&self, _report: &AnalysisReport) -> String {
        todo!()
    }
}
