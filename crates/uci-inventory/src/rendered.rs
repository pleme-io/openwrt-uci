//! Reading back a rendered `InfrastructureTemplate` — the other half of the loop.
//!
//! `emit` produces what the chart declares. This reads what the chart RENDERED,
//! so the pipeline can judge its own output: how many resources, which values,
//! and the Terraform body to hand to an executor.
//!
//! # What this replaced
//!
//! Four separate copies of the same extraction, embedded as Python inside shell
//! scripts. Each copy re-derived the same block-scalar arithmetic, and the
//! failure mode of getting it slightly wrong is not an error — it is a JSON
//! parse of *nearly* the right text, or a resource count quietly short by one.
//!
//! # ★ THIS IS NOT A YAML PARSER, and the distinction is load-bearing
//!
//! It extracts ONE known block from ONE known shape: the literal block scalar
//! under `inline:` in a document containing `kind: InfrastructureTemplate`.
//! It does not resolve anchors, flow mappings, multiple block-scalar styles,
//! or `---` inside a quoted scalar.
//!
//! That narrowness is the honest tier. A general YAML reader is a much larger
//! promise, and claiming one here would be the round-up: it would pass every
//! test written against the chart's own output and fail on the first manifest
//! written by something else. The refusals below exist so an unsupported shape
//! is a REFUSAL rather than a confident wrong answer.

use ubus_facade::json::Json;

/// Why a rendered manifest could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// No document declared `kind: InfrastructureTemplate`.
    NoTemplate,
    /// The template carried no `inline:` block scalar.
    NoInline,
    /// `inline:` was present but not in the literal (`|`) style this reads.
    ///
    /// A REFUSAL rather than a guess: a folded scalar (`>`) joins lines, and
    /// silently folding JSON would produce text that still parses and means
    /// something else.
    NotLiteralBlock(String),
    /// The extracted body was not the JSON the chart promises.
    Body(String),
}

impl core::fmt::Display for RenderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoTemplate => f.write_str(
                "no document with `kind: InfrastructureTemplate` — was this a chart render?",
            ),
            Self::NoInline => f.write_str("the template has no `inline:` body"),
            Self::NotLiteralBlock(got) => {
                f.write_str("`inline:` is not a literal block scalar (expected `|`), got: ")?;
                f.write_str(got)?;
                f.write_str(
                    ". Refused rather than guessed — a folded scalar joins lines, and folded \
                     JSON can still parse while meaning something else.",
                )
            }
            Self::Body(m) => {
                f.write_str("the inline body is not valid JSON: ")?;
                f.write_str(m)
            }
        }
    }
}

/// The raw text of the template's `inline:` block.
///
/// # Errors
///
/// [`RenderError::NoTemplate`], [`RenderError::NoInline`] or
/// [`RenderError::NotLiteralBlock`].
pub fn inline_body(manifest: &str) -> Result<String, RenderError> {
    // Documents are split on a `---` line. See the module note: a `---` inside
    // a quoted scalar would fool this, which is part of why the narrow claim.
    let docs: Vec<&str> = manifest.split("\n---").collect();
    let doc = docs
        .iter()
        .find(|d| d.contains("kind: InfrastructureTemplate"))
        .ok_or(RenderError::NoTemplate)?;

    let mut lines = doc.lines();
    let (indent, style) = loop {
        let Some(l) = lines.next() else {
            return Err(RenderError::NoInline);
        };
        let t = l.trim_start();
        if let Some(rest) = t.strip_prefix("inline:") {
            break (l.len() - t.len(), rest.trim().to_owned());
        }
    };
    if style != "|" {
        return Err(RenderError::NotLiteralBlock(if style.is_empty() {
            "<nothing>".to_owned()
        } else {
            style
        }));
    }

    // A block scalar runs until a line indented no further than its key.
    // Blank lines belong to the block regardless of their own indent.
    let mut out = String::new();
    for l in lines {
        if l.trim().is_empty() {
            out.push('\n');
            continue;
        }
        let li = l.len() - l.trim_start().len();
        if li <= indent {
            break;
        }
        out.push_str(l.get(indent + 2..).unwrap_or_else(|| l.trim_start()));
        out.push('\n');
    }
    Ok(out)
}

/// The Terraform body the template carries, parsed.
///
/// # Errors
///
/// Any [`RenderError`].
pub fn terraform(manifest: &str) -> Result<Json, RenderError> {
    let body = inline_body(manifest)?;
    ubus_facade::json::parse(body.trim()).map_err(|e| RenderError::Body(format!("{e:?}")))
}

/// The `openwrt_uci_section` resources the body declares, as (address, values).
///
/// # Errors
///
/// Any [`RenderError`], or a body without the expected resource block.
pub fn sections(manifest: &str) -> Result<Vec<(String, Json)>, RenderError> {
    let tf = terraform(manifest)?;
    let get = |j: &Json, k: &str| -> Option<Json> {
        match j {
            Json::Obj(p) => p.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()),
            _ => None,
        }
    };
    let res = get(&tf, "resource")
        .and_then(|r| get(&r, "openwrt_uci_section"))
        .ok_or_else(|| RenderError::Body("no resource.openwrt_uci_section".to_owned()))?;
    let Json::Obj(entries) = res else {
        return Err(RenderError::Body(
            "resource.openwrt_uci_section is not an object".to_owned(),
        ));
    };
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RENDER: &str = "apiVersion: v1\nkind: PangeaNamespace\nmetadata:\n  name: t\n---\napiVersion: pangea.pleme.io/v1alpha1\nkind: InfrastructureTemplate\nmetadata:\n  name: roteador-natal\nspec:\n  source:\n    inline: |\n      {\n        \"resource\": {\n          \"openwrt_uci_section\": {\n            \"network_lan\": { \"config\": \"network\", \"values\": { \"proto\": \"static\" } }\n          }\n        }\n      }\n";

    #[test]
    fn finds_the_template_among_several_documents() {
        // The PangeaNamespace comes FIRST in a real render, so a reader that
        // took document 0 would find no inline body at all.
        let tf = terraform(RENDER).expect("extracts");
        assert!(matches!(tf, Json::Obj(_)));
    }

    #[test]
    fn extracts_the_resources() {
        let s = sections(RENDER).expect("sections");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].0, "network_lan");
    }

    #[test]
    fn stops_at_the_end_of_the_block_scalar() {
        // A sibling key at the parent indent must NOT be swallowed into the
        // body — that would make the JSON unparseable and read as a chart bug.
        let with_sibling = format!("{RENDER}  driftDetectionInterval: \"90s\"\n");
        let s = sections(&with_sibling).expect("still parses");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn refuses_a_folded_scalar_rather_than_folding_it() {
        // ★ The refusal that matters: folded JSON can still parse and mean
        // something else, so guessing here is worse than failing.
        let folded = RENDER.replace("inline: |", "inline: >");
        match terraform(&folded) {
            Err(RenderError::NotLiteralBlock(got)) => assert_eq!(got, ">"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn refuses_a_manifest_that_is_not_a_render() {
        assert_eq!(terraform("kind: ConfigMap\n").unwrap_err(), RenderError::NoTemplate);
    }

    #[test]
    fn refuses_a_template_with_no_body() {
        let no_inline = "kind: InfrastructureTemplate\nspec:\n  executor: magma\n";
        assert_eq!(terraform(no_inline).unwrap_err(), RenderError::NoInline);
    }
}
