use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use serde::Deserialize;
use url::Url;

use crate::cli::{BodyOptions, RequestOptions};

#[derive(Debug, Clone, Deserialize)]
pub struct QuestFile {
    quests: BTreeMap<String, QuestCommand>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum QuestUrl {
    Direct { url: Url },
    Composed { base_url: Url, path: String },
}

impl QuestUrl {
    pub fn to_url(&self) -> Result<Url> {
        match self {
            QuestUrl::Direct { url } => Ok(url.clone()),
            QuestUrl::Composed { base_url, path } => {
                // Use Url::join() to properly handle path joining
                base_url.join(path).with_context(|| {
                    format!("Failed to join base URL {} with path {}", base_url, path)
                })
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum QuestCommand {
    Get {
        #[serde(flatten)]
        url_spec: QuestUrl,
        #[serde(flatten)]
        options: RequestOptions,
    },
    Post {
        #[serde(flatten)]
        url_spec: QuestUrl,
        #[serde(flatten)]
        body: BodyOptions,
        #[serde(flatten)]
        options: RequestOptions,
    },
    Put {
        #[serde(flatten)]
        url_spec: QuestUrl,
        #[serde(flatten)]
        body: BodyOptions,
        #[serde(flatten)]
        options: RequestOptions,
    },
    Patch {
        #[serde(flatten)]
        url_spec: QuestUrl,
        #[serde(flatten)]
        body: BodyOptions,
        #[serde(flatten)]
        options: RequestOptions,
    },
    Delete {
        #[serde(flatten)]
        url_spec: QuestUrl,
        #[serde(flatten)]
        options: RequestOptions,
    },
}

impl QuestFile {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read quest file: {}", path.display()))?;

        // Perform environment variable substitution with default value support
        let substituted = shellexpand::env(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to substitute environment variables: {}", e))?
            .to_string();

        // Parse into quests
        let quest_file: QuestFile = serde_saphyr::from_str(&substituted)
            .with_context(|| format!("Failed to parse quest file: {}", path.display()))?;

        log::debug!("Loaded quest file with {} quests", quest_file.quests.len());
        Ok(quest_file)
    }

    pub fn get(&self, name: &str) -> Option<&QuestCommand> {
        self.quests.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &QuestCommand)> {
        self.quests.iter()
    }

    #[allow(dead_code)]
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.quests.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn create_temp_quest_file(content: &str) -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.yaml");
        fs::write(&file_path, content).unwrap();
        (dir, file_path)
    }

    #[test]
    fn test_load_valid_quest_file() {
        let content = r#"
quests:
  test-get:
    method: get
    url: https://example.com/api
"#;
        let (_dir, path) = create_temp_quest_file(content);
        let result = QuestFile::load(&path);

        assert!(result.is_ok());
        let quest_file = result.unwrap();
        assert!(quest_file.get("test-get").is_some());
    }

    #[test]
    fn test_load_nonexistent_file() {
        let path = PathBuf::from("/nonexistent/file.yaml");
        let result = QuestFile::load(&path);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to read quest file")
        );
    }

    #[test]
    fn test_direct_url_parsing() {
        let content = r#"
quests:
  direct:
    method: get
    url: https://example.com/test
"#;
        let (_dir, path) = create_temp_quest_file(content);
        let quest_file = QuestFile::load(&path).unwrap();
        let quest = quest_file.get("direct").unwrap();

        match quest {
            QuestCommand::Get { url_spec, .. } => {
                let url = url_spec.to_url().unwrap();
                assert_eq!(url.as_str(), "https://example.com/test");
            }
            _ => panic!("Expected GET command"),
        }
    }

    #[test]
    fn test_composed_url_parsing() {
        let content = r#"
quests:
  composed:
    method: get
    base_url: https://example.com
    path: /api/v1/users
"#;
        let (_dir, path) = create_temp_quest_file(content);
        let quest_file = QuestFile::load(&path).unwrap();
        let quest = quest_file.get("composed").unwrap();

        match quest {
            QuestCommand::Get { url_spec, .. } => {
                let url = url_spec.to_url().unwrap();
                assert_eq!(url.as_str(), "https://example.com/api/v1/users");
            }
            _ => panic!("Expected GET command"),
        }
    }

    #[test]
    fn test_quest_with_headers() {
        let content = r#"
quests:
  with-headers:
    method: get
    url: https://example.com
    headers:
      - "X-Custom: value"
    user_agent: TestAgent/1.0
"#;
        let (_dir, path) = create_temp_quest_file(content);
        let quest_file = QuestFile::load(&path).unwrap();
        let quest = quest_file.get("with-headers").unwrap();

        match quest {
            QuestCommand::Get { options, .. } => {
                assert_eq!(options.headers.header.len(), 1);
                assert_eq!(
                    options.headers.user_agent,
                    Some("TestAgent/1.0".to_string())
                );
            }
            _ => panic!("Expected GET command"),
        }
    }

    #[test]
    fn test_post_command_parsing() {
        let content = r#"
quests:
  test-post:
    method: post
    url: https://example.com/api
    json: '{"key": "value"}'
"#;
        let (_dir, path) = create_temp_quest_file(content);
        let quest_file = QuestFile::load(&path).unwrap();
        let quest = quest_file.get("test-post").unwrap();

        match quest {
            QuestCommand::Post { body, .. } => {
                assert!(body.json.is_some());
            }
            _ => panic!("Expected POST command"),
        }
    }

    #[test]
    fn test_env_var_substitution() {
        unsafe {
            env::set_var("TEST_QUEST_URL", "https://example.com");
        }

        let content = r#"
quests:
  with-env:
    method: get
    url: ${TEST_QUEST_URL}/api
"#;
        let (_dir, path) = create_temp_quest_file(content);
        let quest_file = QuestFile::load(&path).unwrap();
        let quest = quest_file.get("with-env").unwrap();

        match quest {
            QuestCommand::Get { url_spec, .. } => {
                let url = url_spec.to_url().unwrap();
                assert_eq!(url.as_str(), "https://example.com/api");
            }
            _ => panic!("Expected GET command"),
        }

        unsafe {
            env::remove_var("TEST_QUEST_URL");
        }
    }

    #[test]
    fn test_env_var_with_default() {
        unsafe {
            env::remove_var("TEST_MISSING_VAR");
        }

        let content = r#"
quests:
  with-default:
    method: get
    url: ${TEST_MISSING_VAR:-https://default.com}/api
"#;
        let (_dir, path) = create_temp_quest_file(content);
        let quest_file = QuestFile::load(&path).unwrap();
        let quest = quest_file.get("with-default").unwrap();

        match quest {
            QuestCommand::Get { url_spec, .. } => {
                let url = url_spec.to_url().unwrap();
                assert_eq!(url.as_str(), "https://default.com/api");
            }
            _ => panic!("Expected GET command"),
        }
    }

    #[test]
    fn test_iteration() {
        let content = r#"
quests:
  first:
    method: get
    url: https://example.com/1
  second:
    method: get
    url: https://example.com/2
"#;
        let (_dir, path) = create_temp_quest_file(content);
        let quest_file = QuestFile::load(&path).unwrap();

        let names: Vec<&String> = quest_file.keys().collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&&"first".to_string()));
        assert!(names.contains(&&"second".to_string()));
    }
}
