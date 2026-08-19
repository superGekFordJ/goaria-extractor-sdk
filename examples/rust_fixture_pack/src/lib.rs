use goaria_extractor_sdk::prelude::*;
use std::collections::BTreeMap;

#[goaria_pack]
#[derive(Default)]
pub struct RustFixtureExtractor;

impl Extractor for RustFixtureExtractor {
    fn match_url(&self, input: MatchInput) -> Result<MatchOutput, ExtractorError> {
        if input.url.contains("fixture.invalid") {
            Ok(MatchOutput::matched()
                .with_confidence(100)
                .with_reason("matches fixture.invalid test domain"))
        } else {
            Ok(MatchOutput::unmatched())
        }
    }

    fn extract(&self, input: ExtractInput) -> Result<ExtractOutput, ExtractorError> {
        if !input.url.contains("fixture.invalid") {
            return Ok(ExtractOutput::default());
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("source".to_string(), "rust-fixture-pack".to_string());
        metadata.insert("input_url".to_string(), input.url.clone());

        let item = ExtractedItemRef {
            id: Some("fixture-item-001".to_string()),
            url: Some("https://download.fixture.invalid/artifact.bin".to_string()),
            filename: Some("artifact.bin".to_string()),
            size_bytes: Some(1024),
            mime_type: Some("application/octet-stream".to_string()),
            auth_profile_ref: None,
            header_profile_ref: None,
            metadata: Some(metadata),
        };

        Ok(ExtractOutput::single(item))
    }
}
