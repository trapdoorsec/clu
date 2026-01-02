use crate::output::AnalysisReport;
use crate::output::Formatter;

pub struct TextFormatter {}

impl Formatter for TextFormatter {
    fn format_report(&self, report: &AnalysisReport) -> String {
        todo!()
    }
}