//! Two deterministic agents for the field-inspection demo. Review and filing are
//! rule-based in real life too, so neither needs a model:
//!
//! * [`ReviewExecutor`]: checks an inspection report has the fields it must have and
//!   a valid risk level, and answers `REVIEW: APPROVED` or `REVIEW: NEEDS INFO`.
//! * [`ClaimsExecutor`]: files a report that review approved and returns a claim number
//!   (the same report always gets the same number); anything else is rejected.
//!
//! A report is plain text with labelled lines, which is what the tablet's LLM agent is
//! asked to write:
//!
//! ```text
//! Asset: Boiler 3, Plant Room B
//! Findings: Corrosion on the feed pipe, a small leak at the valve.
//! Risk: High
//! Action: Isolate the valve and replace the pipe within 7 days.
//! ```

use futures_util::future::BoxFuture;

use crate::executor::{ExecContext, ExecEvent, Executor};
use crate::protocol::{AgentSkill, Artifact, Part, TaskState};

const REQUIRED: [&str; 4] = ["Asset", "Findings", "Risk", "Action"];

/// The value of the line labelled `label` (case-insensitive), ignoring list bullets and
/// markdown emphasis that a model may add (`- **Risk:** High`).
pub fn field(text: &str, label: &str) -> Option<String> {
    for line in text.lines() {
        let l = line.trim().trim_start_matches(|c: char| matches!(c, '-' | '*' | '#' | '>' | ' ' | '\t'));
        let l = l.replace("**", "");
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case(label) {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// `low`, `medium` or `high`, if the report's risk line says so.
pub fn risk_level(text: &str) -> Option<&'static str> {
    let v = field(text, "Risk")?.to_lowercase();
    ["high", "medium", "low"].into_iter().find(|level| v.contains(level))
}

pub struct Review {
    pub approved: bool,
    pub missing: Vec<&'static str>,
    pub risk: Option<&'static str>,
    pub asset: Option<String>,
}

pub fn review(text: &str) -> Review {
    let mut missing: Vec<&'static str> = REQUIRED.into_iter().filter(|l| field(text, l).is_none()).collect();
    let risk = risk_level(text);
    if risk.is_none() && !missing.contains(&"Risk") {
        missing.push("Risk (must be low, medium or high)");
    }
    Review { approved: missing.is_empty(), missing, risk, asset: field(text, "Asset") }
}

fn review_text(r: &Review) -> String {
    if r.approved {
        let risk = r.risk.unwrap_or("?").to_uppercase();
        format!(
            "REVIEW: APPROVED\nAsset: {}\nRisk: {risk}\nEscalate: {}",
            r.asset.clone().unwrap_or_default(),
            if r.risk == Some("high") { "yes, within 24 hours" } else { "no" }
        )
    } else {
        format!("REVIEW: NEEDS INFO\nMissing: {}", r.missing.join(", "))
    }
}

/// A stable short id for a report (FNV-1a), so filing the same report twice gives the same number.
pub fn claim_number(text: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in text.trim().bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("CLM-{:08X}", (h >> 32) as u32 ^ h as u32)
}

fn answer(ctx: &ExecContext, name: &str, text: String) {
    let _ = ctx.events.send(ExecEvent::Artifact {
        artifact: Artifact {
            artifact_id: format!("{name}-{}", ctx.task.id),
            name: Some(name.into()),
            description: None,
            parts: vec![Part::text(text)],
            metadata: None,
        },
        append: false,
    });
    ctx.status(TaskState::Completed, None);
}

pub struct ReviewExecutor;

impl Executor for ReviewExecutor {
    fn skills(&self) -> Vec<AgentSkill> {
        vec![AgentSkill {
            id: "review-inspection".into(),
            name: "Review inspection".into(),
            description: "Checks a field inspection report has an asset, findings, a risk level and an action.".into(),
            tags: vec!["review".into(), "rules".into()],
            examples: vec!["Asset: Boiler 3\nFindings: leak\nRisk: High\nAction: replace valve".into()],
        }]
    }

    fn execute(&self, ctx: ExecContext) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let text = ctx.message.text();
            answer(&ctx, "review", review_text(&review(&text)));
        })
    }
}

pub struct ClaimsExecutor;

impl Executor for ClaimsExecutor {
    fn skills(&self) -> Vec<AgentSkill> {
        vec![AgentSkill {
            id: "file-claim".into(),
            name: "File claim".into(),
            description: "Files an approved inspection report and returns a claim number.".into(),
            tags: vec!["claims".into(), "rules".into()],
            examples: vec!["REVIEW: APPROVED\nAsset: Boiler 3\nRisk: HIGH".into()],
        }]
    }

    fn execute(&self, ctx: ExecContext) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let text = ctx.message.text();
            let out = if text.contains("REVIEW: APPROVED") {
                let asset = field(&text, "Asset").unwrap_or_default();
                let risk = field(&text, "Risk").unwrap_or_default();
                format!("CLAIM FILED: {}\nAsset: {asset}\nRisk: {risk}", claim_number(&text))
            } else {
                "NOT FILED: the report was not approved by review.".to_string()
            };
            answer(&ctx, "claim", out);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "Asset: Boiler 3, Plant Room B\nFindings: Corrosion on the feed pipe.\nRisk: High\nAction: Replace the pipe in 7 days.";

    #[test]
    fn fields_are_found_through_bullets_and_markdown() {
        let t = "- **Asset:** Pump 7\n* Findings : worn seal\n## Risk: Medium - monitor\n> Action: order a seal";
        assert_eq!(field(t, "asset").as_deref(), Some("Pump 7"));
        assert_eq!(field(t, "FINDINGS").as_deref(), Some("worn seal"));
        assert_eq!(risk_level(t), Some("medium"));
        assert_eq!(field(t, "action").as_deref(), Some("order a seal"));
        assert_eq!(field(t, "owner"), None);
        assert_eq!(field("Risk:   \nAsset: x", "Risk"), None, "an empty value is not a value");
    }

    #[test]
    fn a_complete_report_is_approved_and_high_risk_escalates() {
        let r = review(GOOD);
        assert!(r.approved && r.missing.is_empty());
        let t = review_text(&r);
        assert!(t.starts_with("REVIEW: APPROVED"));
        assert!(t.contains("Risk: HIGH") && t.contains("Escalate: yes"));
        assert!(review_text(&review(&GOOD.replace("High", "Low"))).contains("Escalate: no"));
    }

    #[test]
    fn an_incomplete_report_says_what_is_missing() {
        let r = review("Asset: Boiler 3\nFindings: leak");
        assert!(!r.approved);
        assert_eq!(r.missing, vec!["Risk", "Action"]);
        assert!(review_text(&r).contains("NEEDS INFO") && review_text(&r).contains("Missing: Risk, Action"));
        // a risk line with no recognisable level is not good enough
        let r = review("Asset: a\nFindings: b\nRisk: unclear\nAction: d");
        assert!(!r.approved && r.missing[0].starts_with("Risk"));
    }

    #[test]
    fn claim_numbers_are_stable_and_distinct() {
        assert_eq!(claim_number(GOOD), claim_number(&format!("  {GOOD}\n")));
        assert_ne!(claim_number(GOOD), claim_number(&GOOD.replace("Boiler 3", "Boiler 4")));
        assert!(claim_number(GOOD).starts_with("CLM-") && claim_number(GOOD).len() == 12);
    }
}
