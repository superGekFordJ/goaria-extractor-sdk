use crate::error::ExtractorError;
use crate::types::{ExtractInput, ExtractOutput, MatchInput, MatchOutput};

/// The `#[goaria_extractor]` macro generates ABI shims that construct the
/// implementor with `Default::default()` on every host invocation, so an
/// extractor cannot rely on constructor arguments or state persisting
/// between calls. The `Send + Sync + 'static` bounds keep the type freely
/// shareable and independent of borrowed lifetimes at the ABI boundary.
///
/// # Invocation order
///
/// The host resolves a URL in two stages: it calls `goaria_match`
/// ([`Extractor::match_url`]) on each candidate pack first and only invokes
/// `goaria_extract` ([`Extractor::extract`]) on a pack whose match output
/// reported `matched: true`. A negative match therefore means `extract` is
/// never reached for that URL.
///
/// # Error mapping on the wire
///
/// ABI v1 has no structured error envelope. A `match_url` `Err` crosses the
/// boundary as `MatchOutput { matched: false, reason: Some(err.to_string()) }`,
/// while an `extract` `Err` decodes host-side as an empty `ExtractOutput` —
/// the error text is dropped. Return `Err` for expected failures; a panic in
/// either method (or in `Default::default()`) aborts under the default
/// `panic = "abort"` strategy as a WebAssembly `unreachable` trap, which the
/// host isolates and reports rather than converts into output.
pub trait Extractor: Default + Send + Sync + 'static {
    /// Runs before [`Extractor::extract`]; the host skips extraction
    /// entirely when the result is `matched: false`.
    ///
    /// # Errors
    /// Returning `Err` reports a negative match with the error text as
    /// `reason` on the wire.
    fn match_url(&self, input: MatchInput) -> Result<MatchOutput, ExtractorError>;

    /// Only invoked after [`Extractor::match_url`] returned `matched: true`
    /// for the same URL.
    ///
    /// # Errors
    /// Returning `Err` produces an empty `ExtractOutput` on the wire; the
    /// error detail is not transmitted to the host.
    fn extract(&self, input: ExtractInput) -> Result<ExtractOutput, ExtractorError>;
}
