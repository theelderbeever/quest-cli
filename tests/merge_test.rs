use duration_string::DurationString;
use quest_cli::cli::{
    AuthOptions, BodyOptions, HeaderOptions, ParamOptions, RequestOptions, TimeoutOptions,
};
use quest_cli::{FormField, StringOrFile};
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

    quest_headers.merge_with(&cli_headers).unwrap();

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

    quest_headers.merge_with(&cli_headers).unwrap();

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

    quest_auth.merge_with(&cli_auth).unwrap();

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

    quest_auth.merge_with(&cli_auth).unwrap();

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

    quest_timeouts.merge_with(&cli_timeouts).unwrap();

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

    quest_options.merge_with(&cli_options).unwrap();

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

    quest_options.merge_with(&cli_options).unwrap();

    // Quest values should remain unchanged
    assert_eq!(quest_options.headers.header.len(), 1);
    assert_eq!(
        quest_options.headers.user_agent,
        Some("QuestAgent".to_string())
    );
}

#[test]
fn test_body_merge_cli_json_overrides_quest_json() {
    let mut quest_body = BodyOptions {
        json: Some(StringOrFile::String(r#"{"quest": "data"}"#.to_string())),
        ..Default::default()
    };

    let cli_body = BodyOptions {
        json: Some(StringOrFile::String(r#"{"cli": "override"}"#.to_string())),
        ..Default::default()
    };

    quest_body.merge_with(&cli_body).unwrap();

    match quest_body.json {
        Some(StringOrFile::String(s)) => assert_eq!(s, r#"{"cli": "override"}"#),
        _ => panic!("Expected String variant"),
    }
}

#[test]
fn test_params_merge_cli_overwrites_at_key_level() {
    let mut quest_params = ParamOptions {
        param: vec!["foo=bar".to_string(), "foo=baz".to_string()],
    };

    let cli_params = ParamOptions {
        param: vec!["foo=qux".to_string()],
    };

    quest_params.merge_with(&cli_params).unwrap();

    // CLI should completely replace quest values for the same key
    assert_eq!(quest_params.param.len(), 1);
    assert!(quest_params.param.contains(&"foo=qux".to_string()));
    assert!(!quest_params.param.contains(&"foo=bar".to_string()));
    assert!(!quest_params.param.contains(&"foo=baz".to_string()));
}

#[test]
fn test_params_merge_allows_multiple_values_per_key() {
    let mut quest_params = ParamOptions {
        param: vec!["tag=rust".to_string(), "tag=cli".to_string()],
    };

    let cli_params = ParamOptions::default();

    quest_params.merge_with(&cli_params).unwrap();

    // Multiple values for same key should coexist
    assert_eq!(quest_params.param.len(), 2);
    assert!(quest_params.param.contains(&"tag=rust".to_string()));
    assert!(quest_params.param.contains(&"tag=cli".to_string()));
}

#[test]
fn test_params_merge_preserves_quest_only_keys() {
    let mut quest_params = ParamOptions {
        param: vec!["foo=bar".to_string(), "hello=world".to_string()],
    };

    let cli_params = ParamOptions {
        param: vec!["baz=qux".to_string()],
    };

    quest_params.merge_with(&cli_params).unwrap();

    // Quest keys not in CLI should be preserved, CLI keys added
    assert_eq!(quest_params.param.len(), 3);
    assert!(quest_params.param.contains(&"foo=bar".to_string()));
    assert!(quest_params.param.contains(&"hello=world".to_string()));
    assert!(quest_params.param.contains(&"baz=qux".to_string()));
}

#[test]
fn test_params_merge_deduplicates_exact_matches() {
    let mut quest_params = ParamOptions {
        param: vec!["foo=bar".to_string(), "foo=bar".to_string()],
    };

    let cli_params = ParamOptions::default();

    quest_params.merge_with(&cli_params).unwrap();

    // Exact duplicates should be deduplicated
    assert_eq!(quest_params.param.len(), 1);
    assert!(quest_params.param.contains(&"foo=bar".to_string()));
}

#[test]
fn test_params_merge_combines_quest_and_cli() {
    let mut quest_params = ParamOptions {
        param: vec![
            "foo=bar".to_string(),
            "hello=world".to_string(),
            "tag=rust".to_string(),
        ],
    };

    let cli_params = ParamOptions {
        param: vec![
            "foo=qux".to_string(),
            "baz=test".to_string(),
            "tag=cli".to_string(),
        ],
    };

    quest_params.merge_with(&cli_params).unwrap();

    // CLI overwrites foo and tag, preserves hello, adds baz
    // Results should be sorted (BTreeMap/BTreeSet ordering)
    assert_eq!(quest_params.param.len(), 4);
    assert!(quest_params.param.contains(&"baz=test".to_string()));
    assert!(quest_params.param.contains(&"foo=qux".to_string()));
    assert!(quest_params.param.contains(&"hello=world".to_string()));
    assert!(quest_params.param.contains(&"tag=cli".to_string()));

    // Verify ordering is alphabetical by key, then value
    assert_eq!(quest_params.param[0], "baz=test");
    assert_eq!(quest_params.param[1], "foo=qux");
    assert_eq!(quest_params.param[2], "hello=world");
    assert_eq!(quest_params.param[3], "tag=cli");
}

#[test]
fn test_params_merge_empty_cli_preserves_quest() {
    let mut quest_params = ParamOptions {
        param: vec!["foo=bar".to_string(), "baz=qux".to_string()],
    };

    let cli_params = ParamOptions::default();

    quest_params.merge_with(&cli_params).unwrap();

    // Empty CLI should leave quest params unchanged
    assert_eq!(quest_params.param.len(), 2);
    assert!(quest_params.param.contains(&"foo=bar".to_string()));
    assert!(quest_params.param.contains(&"baz=qux".to_string()));
}

#[test]
fn test_params_merge_invalid_format_returns_error() {
    let mut quest_params = ParamOptions {
        param: vec!["invalid_param".to_string()],
    };

    let cli_params = ParamOptions::default();

    let result = quest_params.merge_with(&cli_params);

    // Should return error for invalid format
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid parameter format")
    );
}

#[test]
fn test_body_merge_cli_empty_preserves_quest() {
    let mut quest_body = BodyOptions {
        json: Some(StringOrFile::String(r#"{"quest": "data"}"#.to_string())),
        ..Default::default()
    };

    let cli_body = BodyOptions::default();

    quest_body.merge_with(&cli_body).unwrap();

    match quest_body.json {
        Some(StringOrFile::String(s)) => assert_eq!(s, r#"{"quest": "data"}"#),
        _ => panic!("Expected String variant"),
    }
}

#[test]
fn test_body_merge_cli_form_overrides_quest_json() {
    let mut quest_body = BodyOptions {
        json: Some(StringOrFile::String(r#"{"quest": "data"}"#.to_string())),
        ..Default::default()
    };

    let cli_body = BodyOptions {
        form: vec![FormField {
            name: "key".to_string(),
            value: StringOrFile::String("value".to_string()),
        }],
        ..Default::default()
    };

    quest_body.merge_with(&cli_body).unwrap();

    assert!(quest_body.json.is_none());
    assert_eq!(quest_body.form.len(), 1);
    assert_eq!(quest_body.form[0].name, "key");
}

#[test]
fn test_body_merge_cli_raw_overrides_quest_json() {
    let mut quest_body = BodyOptions {
        json: Some(StringOrFile::String(r#"{"quest": "data"}"#.to_string())),
        ..Default::default()
    };

    let cli_body = BodyOptions {
        raw: Some(StringOrFile::String("raw data".to_string())),
        ..Default::default()
    };

    quest_body.merge_with(&cli_body).unwrap();

    assert!(quest_body.json.is_none());
    match quest_body.raw {
        Some(StringOrFile::String(s)) => assert_eq!(s, "raw data"),
        _ => panic!("Expected raw String variant"),
    }
}

#[test]
fn test_request_options_merge_includes_body() {
    let mut quest_options = RequestOptions {
        body: BodyOptions {
            json: Some(StringOrFile::String(r#"{"quest": "data"}"#.to_string())),
            ..Default::default()
        },
        ..Default::default()
    };

    let cli_options = RequestOptions {
        body: BodyOptions {
            json: Some(StringOrFile::String(r#"{"cli": "override"}"#.to_string())),
            ..Default::default()
        },
        ..Default::default()
    };

    quest_options.merge_with(&cli_options).unwrap();

    match quest_options.body.json {
        Some(StringOrFile::String(s)) => assert_eq!(s, r#"{"cli": "override"}"#),
        _ => panic!("Expected String variant"),
    }
}
