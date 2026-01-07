use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(from = "String")]
pub enum StringOrFile {
    String(String),
    File(PathBuf),
}

impl StringOrFile {
    pub fn resolve(&self) -> Result<Vec<u8>> {
        match self {
            StringOrFile::String(s) => Ok(s.as_bytes().to_vec()),
            StringOrFile::File(path) => {
                fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))
            }
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            StringOrFile::String(s) => Some(s),
            StringOrFile::File(_) => None,
        }
    }

    pub fn as_path(&self) -> Option<&Path> {
        match self {
            StringOrFile::String(_) => None,
            StringOrFile::File(path) => Some(path),
        }
    }
}

impl FromStr for StringOrFile {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(path) = s.strip_prefix('@') {
            Ok(StringOrFile::File(PathBuf::from(path)))
        } else {
            Ok(StringOrFile::String(s.to_string()))
        }
    }
}

impl From<String> for StringOrFile {
    fn from(s: String) -> Self {
        StringOrFile::from_str(&s).unwrap()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(from = "String")]
pub struct FormField {
    pub name: String,
    pub value: StringOrFile,
}

impl FromStr for FormField {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, value) = s
            .split_once('=')
            .ok_or_else(|| format!("Invalid form field format: '{}'. Expected 'key=value'", s))?;

        let value = StringOrFile::from_str(value)
            .map_err(|e| format!("Failed to parse form field value: {}", e))?;

        Ok(FormField {
            name: name.to_string(),
            value,
        })
    }
}

impl From<String> for FormField {
    fn from(s: String) -> Self {
        FormField::from_str(&s).unwrap()
    }
}
