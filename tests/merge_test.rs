use duration_string::DurationString;
use quest_cli::cli::{AuthOptions, HeaderOptions, RequestOptions, TimeoutOptions};
use secrecy::{ExposeSecret, SecretString};

// Helper to create SecretString from &str
fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_string().into_boxed_str())
}

#[test]
fn test_header_merge_concatenates() {
    let mut quest_headers = HeaderOptions {
        header: vec!["Content-Type: application/json".to_string()],
        user_agent: Some("QuestAgent/1.0".to_string()),
        ..Default::default()
    };

    let cli_headers = HeaderOptions {
        header: vec!["Authorization: Bearer token".to_string()],
        referer: Some("https://example.com".to_string()),
        ..Default::default()
    };

    quest_headers.merge_with(&cli_headers);

    // Headers should be concatenated
    assert_eq!(quest_headers.header.len(), 2);
    assert!(
        quest_headers
            .header
            .contains(&"Content-Type: application/json".to_string())
    );
    assert!(
        quest_headers
            .header
            .contains(&"Authorization: Bearer token".to_string())
    );

    // CLI scalar values should override
    assert_eq!(
        quest_headers.referer,
        Some("https://example.com".to_string())
    );

    // Quest scalar values should remain if CLI doesn't override
    assert_eq!(quest_headers.user_agent, Some("QuestAgent/1.0".to_string()));
}

#[test]
fn test_header_merge_cli_overrides_scalars() {
    let mut quest_headers = HeaderOptions {
        user_agent: Some("QuestAgent/1.0".to_string()),
        accept: Some("text/plain".to_string()),
        ..Default::default()
    };

    let cli_headers = HeaderOptions {
        user_agent: Some("CLI-Agent/2.0".to_string()),
        ..Default::default()
    };

    quest_headers.merge_with(&cli_headers);

    // CLI user_agent should override quest user_agent
    assert_eq!(quest_headers.user_agent, Some("CLI-Agent/2.0".to_string()));

    // Quest accept should remain (not overridden)
    assert_eq!(quest_headers.accept, Some("text/plain".to_string()));
}

#[test]
fn test_auth_merge_cli_overrides() {
    let mut quest_auth = AuthOptions {
        basic: Some(secret("quest:password")),
        ..Default::default()
    };

    let cli_auth = AuthOptions {
        bearer: Some(secret("cli-token")),
        ..Default::default()
    };

    quest_auth.merge_with(&cli_auth);

    // Both should be present (no conflict)
    assert!(quest_auth.basic.is_some());
    assert!(quest_auth.bearer.is_some());
}

#[test]
fn test_auth_merge_cli_replaces_same_field() {
    let mut quest_auth = AuthOptions {
        bearer: Some(secret("quest-token")),
        ..Default::default()
    };

    let cli_auth = AuthOptions {
        bearer: Some(secret("cli-token")),
        ..Default::default()
    };

    quest_auth.merge_with(&cli_auth);

    // CLI bearer should replace quest bearer
    assert_eq!(
        quest_auth.bearer.as_ref().map(|s| s.expose_secret()),
        Some("cli-token")
    );
}

#[test]
fn test_timeout_merge() {
    let mut quest_timeouts = TimeoutOptions {
        timeout: Some(DurationString::try_from("30s".to_string()).unwrap()),
        connect_timeout: Some(DurationString::try_from("5s".to_string()).unwrap()),
    };

    let cli_timeouts = TimeoutOptions {
        timeout: Some(DurationString::try_from("10s".to_string()).unwrap()),
        ..Default::default()
    };

    quest_timeouts.merge_with(&cli_timeouts);

    // CLI timeout should override
    let timeout_duration: std::time::Duration = quest_timeouts.timeout.unwrap().into();
    assert_eq!(timeout_duration.as_secs(), 10);

    // Quest connect_timeout should remain (not overridden)
    let connect_duration: std::time::Duration = quest_timeouts.connect_timeout.unwrap().into();
    assert_eq!(connect_duration.as_secs(), 5);
}

#[test]
fn test_request_options_merge() {
    let mut quest_options = RequestOptions {
        authorization: AuthOptions {
            basic: Some(secret("quest:pass")),
            ..Default::default()
        },
        headers: HeaderOptions {
            header: vec!["X-Quest-Header: quest".to_string()],
            user_agent: Some("QuestAgent".to_string()),
            ..Default::default()
        },
        timeouts: TimeoutOptions {
            timeout: Some(DurationString::try_from("30s".to_string()).unwrap()),
            ..Default::default()
        },
        ..Default::default()
    };

    let cli_options = RequestOptions {
        authorization: AuthOptions {
            bearer: Some(secret("cli-token")),
            ..Default::default()
        },
        headers: HeaderOptions {
            header: vec!["X-CLI-Header: cli".to_string()],
            referer: Some("https://cli.example.com".to_string()),
            ..Default::default()
        },
        timeouts: TimeoutOptions {
            timeout: Some(DurationString::try_from("10s".to_string()).unwrap()),
            ..Default::default()
        },
        ..Default::default()
    };

    quest_options.merge_with(&cli_options);

    // Headers concatenated
    assert_eq!(quest_options.headers.header.len(), 2);
    assert!(
        quest_options
            .headers
            .header
            .contains(&"X-Quest-Header: quest".to_string())
    );
    assert!(
        quest_options
            .headers
            .header
            .contains(&"X-CLI-Header: cli".to_string())
    );

    // CLI scalar overrides
    assert_eq!(
        quest_options.headers.referer,
        Some("https://cli.example.com".to_string())
    );
    assert_eq!(
        quest_options.headers.user_agent,
        Some("QuestAgent".to_string())
    ); // Not overridden

    // Timeout overridden
    let timeout_duration: std::time::Duration = quest_options.timeouts.timeout.unwrap().into();
    assert_eq!(timeout_duration.as_secs(), 10);

    // Auth merged (both present)
    assert!(quest_options.authorization.basic.is_some());
    assert!(quest_options.authorization.bearer.is_some());
}

#[test]
fn test_empty_cli_options_preserves_quest() {
    let mut quest_options = RequestOptions {
        headers: HeaderOptions {
            header: vec!["X-Quest: value".to_string()],
            user_agent: Some("QuestAgent".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let cli_options = RequestOptions::default();

    quest_options.merge_with(&cli_options);

    // Quest values should remain unchanged
    assert_eq!(quest_options.headers.header.len(), 1);
    assert_eq!(
        quest_options.headers.user_agent,
        Some("QuestAgent".to_string())
    );
}
