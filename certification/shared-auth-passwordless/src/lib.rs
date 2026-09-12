use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasswordlessConsumeRequest {
    pub email: String,
    pub otp: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LegacyConsumeResult {
    Unauthorized,
}

pub fn retained_legacy_bearer_handler() -> LegacyConsumeResult {
    LegacyConsumeResult::Unauthorized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_email_and_otp_only() {
        let request: PasswordlessConsumeRequest =
            serde_json::from_str(r#"{"email":"user@example.com","otp":"123456"}"#).unwrap();
        assert_eq!(request.email, "user@example.com");
        assert_eq!(request.otp, "123456");
    }

    #[test]
    fn rejects_legacy_token_only_body() {
        assert!(
            serde_json::from_str::<PasswordlessConsumeRequest>(r#"{"token":"sat_magic_example"}"#,)
                .is_err()
        );
    }

    #[test]
    fn rejects_mixed_otp_and_legacy_token_body() {
        assert!(
            serde_json::from_str::<PasswordlessConsumeRequest>(
                r#"{"email":"user@example.com","otp":"123456","token":"sat_magic_example"}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn retained_legacy_handler_is_fail_closed() {
        assert_eq!(
            retained_legacy_bearer_handler(),
            LegacyConsumeResult::Unauthorized
        );
    }
}
