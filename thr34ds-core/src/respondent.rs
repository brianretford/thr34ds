//! Respondents, modeled on the **vCard 4.0** schema ([RFC 6350]).
//!
//! In thr34ds a *respondent* is a participant seat in a thread. Every
//! respondent — whether a human or a summoned agent — is represented as a
//! vCard:
//!
//! * a **human** respondent is a vCard with `KIND:individual`;
//! * a **summoned agent** is a vCard with `KIND:application` (vCard 4.0 defines
//!   `application` as "a single software entity, such as an artificial
//!   intelligence or chatbot"). An agent stands in *in lieu of* a human
//!   respondent and **models their behavior**; the human it models is linked via
//!   the vCard `RELATED;TYPE=agent` property.
//!
//! [RFC 6350]: https://www.rfc-editor.org/rfc/rfc6350
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// vCard `KIND` of a respondent.
///
/// Maps directly to the RFC 6350 `KIND` property values. `Application` is used
/// for summoned agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RespondentKind {
    /// A human being (`KIND:individual`).
    Individual,
    /// A group of people (`KIND:group`).
    Group,
    /// An organization (`KIND:org`).
    Org,
    /// A software entity / AI — i.e. a summoned agent (`KIND:application`).
    Application,
}

impl RespondentKind {
    /// The vCard `KIND` token for this variant.
    pub fn as_vcard(&self) -> &'static str {
        match self {
            RespondentKind::Individual => "individual",
            RespondentKind::Group => "group",
            RespondentKind::Org => "org",
            RespondentKind::Application => "application",
        }
    }

    /// Parse a vCard `KIND` token (case-insensitive). Unknown values fall back
    /// to [`RespondentKind::Individual`].
    pub fn from_vcard(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "application" => RespondentKind::Application,
            "group" => RespondentKind::Group,
            "org" => RespondentKind::Org,
            _ => RespondentKind::Individual,
        }
    }

    /// Whether this respondent is a summoned agent (`KIND:application`).
    pub fn is_agent(&self) -> bool {
        matches!(self, RespondentKind::Application)
    }
}

impl Default for RespondentKind {
    fn default() -> Self {
        RespondentKind::Individual
    }
}

/// A respondent seat in a thread, modeled as a vCard.
///
/// Field names mirror vCard 4.0 properties where practical.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Respondent {
    /// vCard `UID`. Stable identifier for the contact.
    pub uid: String,
    /// The thread this respondent participates in.
    pub thread_id: String,
    /// vCard `KIND`.
    pub kind: RespondentKind,
    /// vCard `FN` — the formatted/display name. Required by vCard.
    pub formatted_name: String,
    /// vCard `N` family name component.
    pub family_name: Option<String>,
    /// vCard `N` given name component.
    pub given_name: Option<String>,
    /// vCard `NICKNAME`.
    pub nickname: Option<String>,
    /// vCard `EMAIL`.
    pub email: Option<String>,
    /// vCard `TEL`.
    pub tel: Option<String>,
    /// vCard `ORG`.
    pub org: Option<String>,
    /// vCard `TITLE`.
    pub title: Option<String>,
    /// vCard `ROLE`.
    pub role: Option<String>,
    /// vCard `URL`.
    pub url: Option<String>,
    /// vCard `PHOTO` (URI or data URI).
    pub photo: Option<String>,
    /// vCard `NOTE` — free-form notes.
    pub note: Option<String>,
    /// vCard `CATEGORIES`.
    pub categories: Vec<String>,
    /// For agents: the behavior the agent models, emitted as the
    /// `X-THR34DS-BEHAVIOR` vCard extension property.
    pub behavior: Option<String>,
    /// For agents: the `UID` of the human respondent this agent stands in for,
    /// emitted as `RELATED;TYPE=agent`.
    pub models_uid: Option<String>,
    /// When this respondent was created.
    pub created_at: DateTime<Utc>,
}

impl Respondent {
    /// Create a new human respondent (`KIND:individual`) for a thread.
    pub fn human(uid: impl Into<String>, thread_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(uid, thread_id, RespondentKind::Individual, name)
    }

    /// Create a new agent respondent (`KIND:application`) for a thread. Use
    /// [`Respondent::models`] to link the human it stands in for and
    /// [`Respondent::with_behavior`] to describe the behavior it models.
    pub fn agent(uid: impl Into<String>, thread_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(uid, thread_id, RespondentKind::Application, name)
    }

    fn new(
        uid: impl Into<String>,
        thread_id: impl Into<String>,
        kind: RespondentKind,
        name: impl Into<String>,
    ) -> Self {
        Respondent {
            uid: uid.into(),
            thread_id: thread_id.into(),
            kind,
            formatted_name: name.into(),
            family_name: None,
            given_name: None,
            nickname: None,
            email: None,
            tel: None,
            org: None,
            title: None,
            role: None,
            url: None,
            photo: None,
            note: None,
            categories: Vec::new(),
            behavior: None,
            models_uid: None,
            created_at: Utc::now(),
        }
    }

    /// Set the behavior this agent models (builder-style).
    pub fn with_behavior(mut self, behavior: impl Into<String>) -> Self {
        self.behavior = Some(behavior.into());
        self
    }

    /// Link this agent to the human respondent it stands in for (builder-style).
    pub fn models(mut self, human_uid: impl Into<String>) -> Self {
        self.models_uid = Some(human_uid.into());
        self
    }

    /// Whether this respondent is a summoned agent.
    pub fn is_agent(&self) -> bool {
        self.kind.is_agent()
    }

    /// Serialize this respondent to an RFC 6350 vCard 4.0 string.
    pub fn to_vcard(&self) -> String {
        let mut out = String::from("BEGIN:VCARD\r\nVERSION:4.0\r\n");

        push_line(&mut out, "UID", &format!("urn:uuid:{}", self.uid));
        push_line(&mut out, "KIND", self.kind.as_vcard());
        push_line(&mut out, "FN", &self.formatted_name);

        // N: Family;Given;Additional;Prefix;Suffix
        if self.family_name.is_some() || self.given_name.is_some() {
            let n = format!(
                "{};{};;;",
                escape(self.family_name.as_deref().unwrap_or("")),
                escape(self.given_name.as_deref().unwrap_or("")),
            );
            out.push_str(&format!("N:{n}\r\n"));
        }

        push_opt(&mut out, "NICKNAME", self.nickname.as_deref());
        push_opt(&mut out, "EMAIL", self.email.as_deref());
        push_opt(&mut out, "TEL", self.tel.as_deref());
        push_opt(&mut out, "ORG", self.org.as_deref());
        push_opt(&mut out, "TITLE", self.title.as_deref());
        push_opt(&mut out, "ROLE", self.role.as_deref());
        push_opt(&mut out, "URL", self.url.as_deref());
        push_opt(&mut out, "PHOTO", self.photo.as_deref());
        push_opt(&mut out, "NOTE", self.note.as_deref());

        if !self.categories.is_empty() {
            let joined = self
                .categories
                .iter()
                .map(|c| escape(c))
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!("CATEGORIES:{joined}\r\n"));
        }

        if let Some(behavior) = &self.behavior {
            out.push_str(&format!("X-THR34DS-BEHAVIOR:{}\r\n", escape(behavior)));
        }

        // The human this agent acts in lieu of: RELATED;TYPE=agent.
        if let Some(models) = &self.models_uid {
            out.push_str(&format!("RELATED;TYPE=agent:urn:uuid:{}\r\n", escape(models)));
        }

        out.push_str("END:VCARD\r\n");
        out
    }
}

fn push_line(out: &mut String, prop: &str, value: &str) {
    out.push_str(&format!("{prop}:{}\r\n", escape(value)));
}

fn push_opt(out: &mut String, prop: &str, value: Option<&str>) {
    if let Some(v) = value {
        push_line(out, prop, v);
    }
}

/// Escape a value per RFC 6350 §3.4 (backslash, comma, semicolon, newline).
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ',' => out.push_str("\\,"),
            ';' => out.push_str("\\;"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_is_individual_kind() {
        let r = Respondent::human("u1", "t1", "Ada Lovelace");
        assert_eq!(r.kind, RespondentKind::Individual);
        assert!(!r.is_agent());
        let v = r.to_vcard();
        assert!(v.contains("KIND:individual"));
        assert!(v.contains("FN:Ada Lovelace"));
        assert!(v.contains("UID:urn:uuid:u1"));
    }

    #[test]
    fn agent_is_application_and_links_to_human() {
        let agent = Respondent::agent("a1", "t1", "Ada (agent)")
            .models("u1")
            .with_behavior("Answers as a meticulous 19th-century mathematician.");
        assert!(agent.is_agent());
        let v = agent.to_vcard();
        assert!(v.contains("KIND:application"));
        assert!(v.contains("RELATED;TYPE=agent:urn:uuid:u1"));
        assert!(v.contains("X-THR34DS-BEHAVIOR:Answers as a meticulous"));
    }

    #[test]
    fn vcard_has_begin_end_and_version() {
        let v = Respondent::human("u1", "t1", "Test").to_vcard();
        assert!(v.starts_with("BEGIN:VCARD\r\nVERSION:4.0\r\n"));
        assert!(v.trim_end().ends_with("END:VCARD"));
    }

    #[test]
    fn special_chars_are_escaped() {
        let mut r = Respondent::human("u1", "t1", "Doe, John; Jr.");
        r.note = Some("line1\nline2".into());
        let v = r.to_vcard();
        assert!(v.contains("FN:Doe\\, John\\; Jr."));
        assert!(v.contains("NOTE:line1\\nline2"));
    }

    #[test]
    fn kind_roundtrips() {
        for k in ["individual", "application", "group", "org"] {
            assert_eq!(RespondentKind::from_vcard(k).as_vcard(), k);
        }
        // Unknown falls back to individual.
        assert_eq!(RespondentKind::from_vcard("bogus"), RespondentKind::Individual);
    }
}
