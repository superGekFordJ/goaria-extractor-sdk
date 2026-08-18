use crate::error::ExtractorError;
use crate::types::{ExtractInput, ExtractOutput, MatchInput, MatchOutput};

/// The primary trait implemented by GoAria URL extractors.
pub trait Extractor: Default + Send + Sync + 'static {
    /// Evaluate whether this extractor can handle the given URL.
    fn match_url(&self, input: MatchInput) -> Result<MatchOutput, ExtractorError>;

    /// Extract downloadable resource items from the URL.
    fn extract(&self, input: ExtractInput) -> Result<ExtractOutput, ExtractorError>;
}
