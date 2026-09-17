use goaria_extractor_sdk::prelude::*;
use std::collections::BTreeMap;

const IMGUR_BROKER_POLICY_REF: &str = "bpr-imgur01";
const IMGUR_ENDPOINT_REF: &str = "ep-imgur01";

#[goaria_extractor]
#[derive(Default)]
pub struct ImgurExtractor;

impl Extractor for ImgurExtractor {
    fn match_url(&self, input: MatchInput) -> Result<MatchOutput, ExtractorError> {
        if parse_imgur_content_id(&input.url).is_some() {
            Ok(MatchOutput::matched()
                .with_confidence(100)
                .with_reason("matches imgur.com share URL"))
        } else {
            Ok(MatchOutput::unmatched())
        }
    }

    fn extract(&self, input: ExtractInput) -> Result<ExtractOutput, ExtractorError> {
        let content_id = match parse_imgur_content_id(&input.url) {
            Some(id) => id,
            None => return Ok(ExtractOutput::default()),
        };

        // If it's already a direct i.imgur.com URL, return it directly
        if is_valid_direct_imgur_url(&input.url) {
            if let Some(clean_url) = clean_direct_url(&input.url) {
                if let Some(filename) = extract_filename_from_url(&clean_url) {
                    let mime_type = mime_type_for_filename(&filename);
                    let item = ExtractedItemRef {
                        id: Some(content_id),
                        url: Some(clean_url),
                        filename: Some(filename),
                        size_bytes: None,
                        mime_type: mime_type.map(|m| m.to_string()),
                        auth_profile_ref: None,
                        header_profile_ref: None,
                        download_auth_ref: None,
                        metadata: None,
                    };
                    return Ok(ExtractOutput::single(item));
                }
            }
        }

        let broker = HostBroker::new();
        let mut params = BTreeMap::new();
        params.insert("id".to_string(), content_id.clone());

        // Alias Ref-Mode: url must be None, host expands endpoint_ref template
        let req = HostHTTPFetchRequest {
            url: None,
            method: Some("GET".to_string()),
            broker_policy_ref: Some(IMGUR_BROKER_POLICY_REF.to_string()),
            endpoint_ref: Some(IMGUR_ENDPOINT_REF.to_string()),
            params: Some(params),
            ..Default::default()
        };

        let body = match broker.fetch_text(&req) {
            Ok(text) => text,
            Err(_) => return Ok(ExtractOutput::default()),
        };

        if has_forbidden_secret_markers(&body) {
            return Ok(ExtractOutput::default());
        }

        let direct_url = match find_direct_image_url(&body) {
            Some(url) => url,
            None => return Ok(ExtractOutput::default()),
        };

        let clean_url = match clean_direct_url(&direct_url) {
            Some(u) => u,
            None => return Ok(ExtractOutput::default()),
        };

        if !is_valid_direct_imgur_url(&clean_url) {
            return Ok(ExtractOutput::default());
        }

        let filename = match extract_filename_from_url(&clean_url) {
            Some(f) => f,
            None => return Ok(ExtractOutput::default()),
        };

        let mime_type = match mime_type_for_filename(&filename) {
            Some(m) => m,
            None => return Ok(ExtractOutput::default()),
        };

        let item = ExtractedItemRef {
            id: Some(content_id),
            url: Some(clean_url),
            filename: Some(filename),
            size_bytes: None,
            mime_type: Some(mime_type.to_string()),
            auth_profile_ref: None,
            header_profile_ref: None,
            download_auth_ref: None,
            metadata: None,
        };

        Ok(ExtractOutput::single(item))
    }
}

fn parse_imgur_content_id(raw_url: &str) -> Option<String> {
    let trimmed = raw_url.trim();
    let url_without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))?;

    let (host_and_path, _query_or_frag) = url_without_scheme
        .split_once('?')
        .map(|(hp, _)| (hp, ""))
        .or_else(|| url_without_scheme.split_once('#').map(|(hp, _)| (hp, "")))
        .unwrap_or((url_without_scheme, ""));

    let (host, path) = match host_and_path.split_once('/') {
        Some((h, p)) => (h.trim().to_lowercase(), p),
        None => return None,
    };

    let host_no_port = host.split(':').next().unwrap_or("");
    if host_no_port != "imgur.com"
        && host_no_port != "i.imgur.com"
        && !host_no_port.ends_with(".imgur.com")
    {
        return None;
    }

    let mut segments = path.split('/').filter(|s| !s.is_empty());
    let first = segments.next()?.trim();

    let raw_id = match first {
        "a" | "gallery" | "t" | "r" => {
            let second = segments.next()?.trim();
            second
        }
        other => other,
    };

    let id_without_ext = raw_id.split('.').next().unwrap_or("").trim();
    if id_without_ext.is_empty() {
        return None;
    }

    // If slug has title prefix like "brb-off-to-bother-town-wizard-VFnCfiB", extract the last token "VFnCfiB"
    let real_id = if id_without_ext.contains('-') {
        id_without_ext.rsplit('-').next().unwrap_or(id_without_ext)
    } else {
        id_without_ext
    };

    if !real_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }

    Some(real_id.to_string())
}

fn clean_direct_url(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let without_query = trimmed.split('?').next()?.split('#').next()?;
    Some(without_query.to_string())
}

fn find_direct_image_url(body: &str) -> Option<String> {
    // 1. Check video stream meta tags (for mp4/gifv)
    if let Some(url) = find_meta_property_content(body, "twitter:player:stream") {
        if let Some(clean) = clean_direct_url(&url) {
            if is_valid_direct_imgur_url(&clean) {
                return Some(clean);
            }
        }
    }
    // 2. Check OpenGraph image
    if let Some(url) = find_meta_property_content(body, "og:image") {
        if let Some(clean) = clean_direct_url(&url) {
            if is_valid_direct_imgur_url(&clean) {
                return Some(clean);
            }
        }
    }
    // 3. Check Twitter image
    if let Some(url) = find_meta_property_content(body, "twitter:image") {
        if let Some(clean) = clean_direct_url(&url) {
            if is_valid_direct_imgur_url(&clean) {
                return Some(clean);
            }
        }
    }
    // 4. Check link rel="image_src"
    if let Some(url) = find_link_tag_href(body, "image_src") {
        if let Some(clean) = clean_direct_url(&url) {
            if is_valid_direct_imgur_url(&clean) {
                return Some(clean);
            }
        }
    }
    // 5. Check JSON field "url" or "link"
    if let Some(url) = find_json_field_url(body, "url") {
        if let Some(clean) = clean_direct_url(&url) {
            if is_valid_direct_imgur_url(&clean) {
                return Some(clean);
            }
        }
    }
    if let Some(url) = find_json_field_url(body, "direct_link") {
        if let Some(clean) = clean_direct_url(&url) {
            if is_valid_direct_imgur_url(&clean) {
                return Some(clean);
            }
        }
    }
    None
}

fn find_meta_property_content(body: &str, property_name: &str) -> Option<String> {
    let patterns = [
        format!("property=\"{}\"", property_name),
        format!("property='{}'", property_name),
        format!("name=\"{}\"", property_name),
        format!("name='{}'", property_name),
    ];

    for pat in &patterns {
        let mut search_from = 0;
        while let Some(pos) = body[search_from..].find(pat) {
            let start = search_from + pos;
            let tag_start = body[..start].rfind('<').unwrap_or(start);
            let tag_end = body[start..]
                .find('>')
                .map(|e| start + e)
                .unwrap_or(body.len());
            let tag = &body[tag_start..tag_end];

            if let Some(content) = extract_attr_from_tag(tag, "content") {
                return Some(content);
            }

            search_from = start + pat.len();
        }
    }

    None
}

fn find_link_tag_href(body: &str, rel_value: &str) -> Option<String> {
    let patterns = [
        format!("rel=\"{}\"", rel_value),
        format!("rel='{}'", rel_value),
    ];

    for pat in &patterns {
        let mut search_from = 0;
        while let Some(pos) = body[search_from..].find(pat) {
            let start = search_from + pos;
            let tag_start = body[..start].rfind('<').unwrap_or(start);
            let tag_end = body[start..]
                .find('>')
                .map(|e| start + e)
                .unwrap_or(body.len());
            let tag = &body[tag_start..tag_end];

            if let Some(href) = extract_attr_from_tag(tag, "href") {
                return Some(href);
            }

            search_from = start + pat.len();
        }
    }

    None
}

fn extract_attr_from_tag(tag: &str, attr: &str) -> Option<String> {
    let double_q = format!("{}=\"", attr);
    let single_q = format!("{}='", attr);

    if let Some(idx) = tag.find(&double_q) {
        let after = &tag[idx + double_q.len()..];
        if let Some(end) = after.find('"') {
            return Some(after[..end].to_string());
        }
    }
    if let Some(idx) = tag.find(&single_q) {
        let after = &tag[idx + single_q.len()..];
        if let Some(end) = after.find('\'') {
            return Some(after[..end].to_string());
        }
    }
    None
}

fn find_json_field_url(body: &str, field: &str) -> Option<String> {
    let key_marker = format!("\"{}\":", field);
    if let Some(idx) = body.find(&key_marker) {
        let after = body[idx + key_marker.len()..].trim_start();
        if let Some(stripped) = after.strip_prefix('"') {
            if let Some(end) = stripped.find('"') {
                return Some(stripped[..end].replace("\\/", "/"));
            }
        }
    }
    None
}

fn is_valid_direct_imgur_url(url: &str) -> bool {
    let trimmed = url.trim();
    let after_prefix = if let Some(stripped) = trimmed.strip_prefix("https://i.imgur.com/") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("http://i.imgur.com/") {
        stripped
    } else {
        return false;
    };

    let without_query = after_prefix.split('?').next().unwrap_or(after_prefix);
    if without_query.is_empty() || without_query.contains('/') || without_query.contains("..") {
        return false;
    }

    let filename = match extract_filename_from_url(trimmed) {
        Some(f) => f,
        None => return false,
    };

    mime_type_for_filename(&filename).is_some()
}

fn extract_filename_from_url(url: &str) -> Option<String> {
    let path = url.split('?').next().unwrap_or(url);
    let filename = path.rsplit('/').next().unwrap_or("");
    let trimmed = filename.trim();
    if trimmed.is_empty() || trimmed.len() > 255 || trimmed.contains("..") {
        return None;
    }
    if trimmed.chars().any(|c| c.is_ascii_control()) {
        return None;
    }
    Some(trimmed.to_string())
}

fn mime_type_for_filename(filename: &str) -> Option<&'static str> {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        Some("image/jpeg")
    } else if lower.ends_with(".png") {
        Some("image/png")
    } else if lower.ends_with(".gif") {
        Some("image/gif")
    } else if lower.ends_with(".mp4") {
        Some("video/mp4")
    } else if lower.ends_with(".webp") {
        Some("image/webp")
    } else {
        None
    }
}

fn has_forbidden_secret_markers(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("authorization:")
        || lower.contains("bearer raw-")
        || lower.contains("client-id raw-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_imgur_content_id() {
        assert_eq!(
            parse_imgur_content_id("https://imgur.com/sample123"),
            Some("sample123".to_string())
        );
        assert_eq!(
            parse_imgur_content_id("https://imgur.com/a/album456"),
            Some("album456".to_string())
        );
        assert_eq!(
            parse_imgur_content_id("https://imgur.com/gallery/gallery789"),
            Some("gallery789".to_string())
        );
        assert_eq!(
            parse_imgur_content_id(
                "https://imgur.com/gallery/brb-off-to-bother-town-wizard-VFnCfiB"
            ),
            Some("VFnCfiB".to_string())
        );
        assert_eq!(
            parse_imgur_content_id("http://i.imgur.com/photo.png"),
            Some("photo".to_string())
        );
        assert_eq!(
            parse_imgur_content_id("https://example.com/sample123"),
            None
        );
        assert_eq!(parse_imgur_content_id("invalid-url"), None);
    }

    #[test]
    fn test_find_direct_image_url_og() {
        let html = r#"<html><head><meta property="og:image" content="https://i.imgur.com/sample123.jpg?fbplay" /></head></html>"#;
        assert_eq!(
            find_direct_image_url(html),
            Some("https://i.imgur.com/sample123.jpg".to_string())
        );

        let twitter_video_html = r#"<html><head><meta name="twitter:player:stream" content="https://i.imgur.com/DOuSYXf.mp4"></head></html>"#;
        assert_eq!(
            find_direct_image_url(twitter_video_html),
            Some("https://i.imgur.com/DOuSYXf.mp4".to_string())
        );
    }

    #[test]
    fn test_is_valid_direct_imgur_url() {
        assert!(is_valid_direct_imgur_url("https://i.imgur.com/abc1234.jpg"));
        assert!(is_valid_direct_imgur_url(
            "https://i.imgur.com/abc1234.jpg?fbplay"
        ));
        assert!(is_valid_direct_imgur_url("https://i.imgur.com/abc1234.mp4"));
        assert!(!is_valid_direct_imgur_url("https://evil.com/abc.jpg"));
        assert!(!is_valid_direct_imgur_url(
            "https://i.imgur.com/sub/abc.jpg"
        ));
    }
}
