use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use duration_string::DurationString;
use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

use crate::{
    builder::{QuestClientBuilder, QuestRequestBuilder},
    quest::{QuestCommand, QuestFile, QuestUrl},
    types::{FormField, StringOrFile},
};

#[derive(Clone, Debug, Parser)]
#[command(name = "quest")]
#[command(version, about = "Cli for all the http fetch (re)quests you may go on.", long_about = None)]
pub struct QuestCli {
    #[arg(
        short,
        long,
        global = true,
        default_value = ".env",
        help = "Load environment variables from file"
    )]
    env: PathBuf,
    #[clap(flatten)]
    pub options: RequestOptions,

    #[command(subcommand)]
    command: Command,
}

impl QuestCli {
    pub fn init_logging(self) -> Self {
        env_logger::init();
        self
    }
    fn list_quests(quest_file: QuestFile) -> Result<()> {
        use colored::Colorize;
        use std::io::Write;

        // Collect quest data for formatting
        let mut quest_data: Vec<(String, String, String)> = Vec::new();

        for (name, command) in quest_file.iter() {
            let (method, url) = match command {
                QuestCommand::Get { url_spec, .. } => ("GET", url_spec.to_url()?),
                QuestCommand::Post { url_spec, .. } => ("POST", url_spec.to_url()?),
                QuestCommand::Put { url_spec, .. } => ("PUT", url_spec.to_url()?),
                QuestCommand::Delete { url_spec, .. } => ("DELETE", url_spec.to_url()?),
                QuestCommand::Patch { url_spec, .. } => ("PATCH", url_spec.to_url()?),
            };

            quest_data.push((name.clone(), method.to_string(), url.to_string()));
        }

        let stdout = std::io::stdout();
        let mut handle = stdout.lock();

        if quest_data.is_empty() {
            writeln!(handle, "No quests found in the quest file.")?;
            return Ok(());
        }

        // Calculate column widths
        let max_name_width = quest_data
            .iter()
            .map(|(name, _, _)| name.len())
            .max()
            .unwrap_or(4)
            .max(4); // "NAME" header is 4 chars

        let max_method_width = 6; // "DELETE" is longest method

        // Print header
        writeln!(
            handle,
            "{:<name_width$}  {:<method_width$}  {}",
            "NAME".bold(),
            "METHOD".bold(),
            "URL".bold(),
            name_width = max_name_width,
            method_width = max_method_width
        )?;

        // Print separator
        writeln!(
            handle,
            "{}  {}  {}",
            "─".repeat(max_name_width),
            "─".repeat(max_method_width),
            "─".repeat(40)
        )?;

        // Print each quest
        for (name, method, url) in quest_data {
            let colored_method = match method.as_str() {
                "GET" => method.green().bold(),
                "POST" => method.blue().bold(),
                "PUT" => method.yellow().bold(),
                "DELETE" => method.red().bold(),
                "PATCH" => method.magenta().bold(),
                _ => method.white().bold(),
            };

            writeln!(
                handle,
                "{:<name_width$}  {:<method_width$}  {}",
                name.cyan(),
                colored_method,
                url.bright_black(),
                name_width = max_name_width,
                method_width = max_method_width
            )?;
        }

        handle.flush()?;
        Ok(())
    }

    pub fn execute(self) -> Result<()> {
        // Load environment variables from file if it exists
        if self.env.exists() {
            dotenvy::from_path(&self.env).ok();
            log::debug!("Loaded environment variables from {}", self.env.display());
        }

        let options = self.options;
        match self.command {
            Command::List { file } => {
                // Load quest file
                let quest_file = QuestFile::load(&file)
                    .with_context(|| format!("Failed to load quest file: {}", file.display()))?;

                Self::list_quests(quest_file)?;
                Ok(())
            }
            Command::Go { name, file } => {
                // 1. Load quest file
                let quest_file = QuestFile::load(&file)
                    .with_context(|| format!("Failed to load quest file: {}", file.display()))?;

                // 2. Find quest by name
                let quest_command = quest_file
                    .get(&name)
                    .ok_or_else(|| anyhow::anyhow!("Quest '{}' not found.", name))?
                    .clone();

                // 3. Execute the quest command (merging happens in execute_quest_command)
                log::info!("Executing quest '{}' from {}", name, file.display());
                Self::execute_quest_command(options, quest_command)
            }
            Command::Get { url } => {
                let quest = QuestCommand::Get {
                    url_spec: QuestUrl::Direct { url },
                    options: RequestOptions::default(),
                };
                Self::execute_quest_command(options, quest)
            }
            Command::Post { url } => {
                let quest = QuestCommand::Post {
                    url_spec: QuestUrl::Direct { url },
                    body: BodyOptions::default(),
                    options: RequestOptions::default(),
                };
                Self::execute_quest_command(options, quest)
            }
            Command::Put { url } => {
                let quest = QuestCommand::Put {
                    url_spec: QuestUrl::Direct { url },
                    body: BodyOptions::default(),
                    options: RequestOptions::default(),
                };
                Self::execute_quest_command(options, quest)
            }
            Command::Delete { url } => {
                let quest = QuestCommand::Delete {
                    url_spec: QuestUrl::Direct { url },
                    options: RequestOptions::default(),
                };
                Self::execute_quest_command(options, quest)
            }
            Command::Patch { url } => {
                let quest = QuestCommand::Patch {
                    url_spec: QuestUrl::Direct { url },
                    body: BodyOptions::default(),
                    options: RequestOptions::default(),
                };
                Self::execute_quest_command(options, quest)
            }
        }
    }

    fn log_request_verbose(
        url: &Url,
        method: &str,
        headers: &HeaderOptions,
        auth: &AuthOptions,
    ) -> Result<()> {
        use colored::Colorize;
        use std::io::Write;

        let stderr = std::io::stderr();
        let mut handle = stderr.lock();

        // Request line in cyan/bold
        writeln!(
            handle,
            "{} {} HTTP/1.1",
            method.cyan().bold(),
            url.as_str().cyan().bold()
        )?;

        // Headers in blue
        writeln!(
            handle,
            "{} {}",
            "Host:".blue(),
            url.host_str().unwrap_or("unknown")
        )?;

        // Show headers that will be sent
        if let Some(user_agent) = &headers.user_agent {
            writeln!(handle, "{} {}", "User-Agent:".blue(), user_agent)?;
        } else {
            writeln!(handle, "{} quest/0.1.0", "User-Agent:".blue())?;
        }

        for header in &headers.header {
            if let Some((key, value)) = header.split_once(':') {
                writeln!(
                    handle,
                    "{} {}",
                    format!("{}:", key.trim()).blue(),
                    value.trim()
                )?;
            }
        }

        // Log authorization headers with redaction
        if auth.bearer.is_some() {
            writeln!(handle, "{} Bearer [REDACTED]", "Authorization:".blue())?;
        } else if auth.auth.is_some() || auth.basic.is_some() {
            writeln!(handle, "{} Basic [REDACTED]", "Authorization:".blue())?;
        }

        // Log Referer header if present
        if let Some(referer) = &headers.referer {
            writeln!(handle, "{} {}", "Referer:".blue(), referer)?;
        }

        if let Some(accept) = &headers.accept {
            writeln!(handle, "{} {}", "Accept:".blue(), accept)?;
        }

        if let Some(content_type) = &headers.content_type {
            writeln!(handle, "{} {}", "Content-Type:".blue(), content_type)?;
        }

        writeln!(handle)?;
        handle.flush()?;
        Ok(())
    }

    fn log_response_verbose(response: &reqwest::blocking::Response) -> Result<()> {
        use colored::Colorize;
        use std::io::Write;

        let stderr = std::io::stderr();
        let mut handle = stderr.lock();

        // Status line in green/bold for success, red/bold for errors
        let status = response.status();
        let status_line = format!(
            "HTTP/1.1 {} {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("")
        );

        if status.is_success() {
            writeln!(handle, "{}", status_line.green().bold())?;
        } else if status.is_client_error() || status.is_server_error() {
            writeln!(handle, "{}", status_line.red().bold())?;
        } else {
            writeln!(handle, "{}", status_line.cyan().bold())?;
        }

        // Headers in cyan
        for (name, value) in response.headers() {
            if let Ok(val_str) = value.to_str() {
                writeln!(handle, "{} {}", format!("{}:", name).cyan(), val_str)?;
            }
        }

        writeln!(handle)?;
        handle.flush()?;
        Ok(())
    }

    fn execute_quest_command(cli_options: RequestOptions, quest: QuestCommand) -> Result<()> {
        // 1. Extract quest file options and body, transfer body into options
        let (mut quest_options, quest_body) = match &quest {
            QuestCommand::Get { options, .. } => (options.clone(), None),
            QuestCommand::Post { options, body, .. } => (options.clone(), Some(body)),
            QuestCommand::Put { options, body, .. } => (options.clone(), Some(body)),
            QuestCommand::Delete { options, .. } => (options.clone(), None),
            QuestCommand::Patch { options, body, .. } => (options.clone(), Some(body)),
        };

        // Transfer quest body into quest_options before merge
        if let Some(body) = quest_body {
            quest_options.body = body.clone();
        }

        // 2. Merge quest options (including body) with CLI options
        quest_options.merge_with(&cli_options)?;

        // 3. Build the client with merged options
        let client = QuestClientBuilder::new().apply(&quest_options)?.build()?;

        // 4. Build the request based on the quest command
        let (request_builder, method, url) = match &quest {
            QuestCommand::Get { url_spec, .. } => {
                let url = url_spec.to_url()?;
                (client.get(url.as_str()), "GET", url)
            }
            QuestCommand::Post { url_spec, .. } => {
                let url = url_spec.to_url()?;
                (client.post(url.as_str()), "POST", url)
            }
            QuestCommand::Put { url_spec, .. } => {
                let url = url_spec.to_url()?;
                (client.put(url.as_str()), "PUT", url)
            }
            QuestCommand::Delete { url_spec, .. } => {
                let url = url_spec.to_url()?;
                (client.delete(url.as_str()), "DELETE", url)
            }
            QuestCommand::Patch { url_spec, .. } => {
                let url = url_spec.to_url()?;
                (client.patch(url.as_str()), "PATCH", url)
            }
        };

        // Show request details if verbose
        if quest_options.output.verbose {
            Self::log_request_verbose(
                &url,
                method,
                &quest_options.headers,
                &quest_options.authorization,
            )?;
        }

        // 5. Apply merged options (including body) to request
        let request = QuestRequestBuilder::from_request(request_builder).apply(&quest_options)?;

        // 6. Send the request
        let response = request.send()?;

        // 7. Handle the response
        Self::handle_response(response, &quest_options.output)?;

        Ok(())
    }

    fn handle_response(
        response: reqwest::blocking::Response,
        output_opts: &OutputOptions,
    ) -> Result<()> {
        use std::io::Write;

        if output_opts.verbose {
            Self::log_response_verbose(&response)?;
        }

        let content = response.bytes()?;

        let output = if !output_opts.simple
            && output_opts.output.is_none()
            && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&content)
            && let Ok(formatted) = colored_json::to_colored_json_auto(&json)
        {
            Output::Text(formatted)
        } else if let Ok(text) = String::from_utf8(content.to_vec()) {
            Output::Text(text)
        } else {
            Output::Bytes(content.to_vec())
        };

        match (output, &output_opts.output) {
            (output, Some(path)) => {
                let bytes = output.into_bytes();
                let mut file = std::fs::File::create(path)
                    .with_context(|| format!("Failed to create output file: {}", path.display()))?;
                file.write_all(&bytes)?;
            }
            (Output::Text(s), None) => {
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "{s}").or_else(|e| {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })?
            }
            (Output::Bytes(v), None) => {
                anyhow::bail!("[Binary data: {} bytes - use --output to save]", v.len());
            }
        }

        Ok(())
    }
}

enum Output {
    Text(String),
    Bytes(Vec<u8>),
}

impl Output {
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Bytes(v) => v,
            Self::Text(s) => s.into_bytes(),
        }
    }
}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    Get {
        url: Url,
    },
    Post {
        url: Url,
    },
    Put {
        url: Url,
    },
    Delete {
        url: Url,
    },
    Patch {
        url: Url,
    },
    /// Run a named quest from a quest file
    Go {
        /// Quest name to execute
        name: String,

        #[arg(
            short,
            long,
            default_value = ".quests.yaml",
            help = "Quest file to load from"
        )]
        file: PathBuf,
    },
    /// List all quests from a quest file
    List {
        #[arg(
            short,
            long,
            default_value = ".quests.yaml",
            help = "Quest file to load from"
        )]
        file: PathBuf,
    },
}

#[derive(Debug, Args, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RequestOptions {
    #[serde(flatten)]
    #[clap(flatten)]
    pub authorization: AuthOptions,
    #[serde(flatten)]
    #[clap(flatten)]
    pub headers: HeaderOptions,
    #[serde(flatten)]
    #[clap(flatten)]
    pub params: ParamOptions,
    #[serde(flatten)]
    #[clap(flatten)]
    pub body: BodyOptions,
    #[serde(flatten)]
    #[clap(flatten)]
    pub timeouts: TimeoutOptions,
    #[serde(flatten)]
    #[clap(flatten)]
    pub redirects: RedirectOptions,
    #[serde(flatten)]
    #[clap(flatten)]
    pub tls: TlsOptions,
    #[serde(flatten)]
    #[clap(flatten)]
    pub proxy: ProxyOptions,
    #[serde(flatten)]
    #[clap(flatten)]
    pub output: OutputOptions,
    #[serde(flatten)]
    #[clap(flatten)]
    pub compression: CompressionOptions,
}

#[derive(Debug, Args, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AuthOptions {
    #[arg(short, long, global = true)]
    pub auth: Option<SecretString>,
    #[arg(long, global = true)]
    pub basic: Option<SecretString>,
    #[arg(long, global = true)]
    pub bearer: Option<SecretString>,
}

#[derive(Debug, Args, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HeaderOptions {
    #[serde(rename = "headers")]
    #[arg(
        short = 'H',
        long = "header",
        global = true,
        help = "Custom header (repeatable)"
    )]
    pub header: Vec<String>,
    #[arg(
        short = 'U',
        long = "user-agent",
        global = true,
        help = "Set User-Agent header"
    )]
    pub user_agent: Option<String>,
    #[arg(
        short = 'R',
        long = "referer",
        global = true,
        help = "Set Referer header"
    )]
    pub referer: Option<String>,
    #[arg(long = "content-type", global = true, help = "Set Content-Type header")]
    pub content_type: Option<String>,
    #[arg(long = "accept", global = true, help = "Set Accept header")]
    pub accept: Option<String>,
}

#[derive(Debug, Args, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ParamOptions {
    #[serde(rename = "params")]
    #[arg(
        short = 'p',
        long = "param",
        global = true,
        help = "Query parameter (repeatable)"
    )]
    pub param: Vec<String>,
}

#[derive(Debug, Args, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TimeoutOptions {
    #[arg(
        short = 't',
        long = "timeout",
        global = true,
        help = "Overall request timeout (e.g., '30s', '1m')"
    )]
    pub timeout: Option<DurationString>,
    #[arg(
        long = "connect-timeout",
        global = true,
        help = "Connection timeout (e.g., '10s')"
    )]
    pub connect_timeout: Option<DurationString>,
}

#[derive(Debug, Args, Clone, Default, Deserialize)]
#[serde(default)]
pub struct BodyOptions {
    #[arg(
        short = 'j',
        long = "json",
        group = "body",
        global = true,
        help = "Send data as JSON (auto sets Content-Type)",
        value_hint = clap::ValueHint::FilePath
    )]
    pub json: Option<StringOrFile>,
    #[arg(
        short = 'F',
        long = "form",
        group = "body",
        global = true,
        help = "Form data (repeatable)"
    )]
    pub form: Vec<FormField>,
    #[arg(
        long = "raw",
        group = "body",
        global = true,
        help = "Send raw data without processing",
        value_hint = clap::ValueHint::FilePath
    )]
    pub raw: Option<StringOrFile>,
    #[arg(
        long = "binary",
        group = "body",
        global = true,
        help = "Send binary data",
        value_hint = clap::ValueHint::FilePath
    )]
    pub binary: Option<StringOrFile>,
}

#[derive(Debug, Args, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RedirectOptions {
    #[arg(
        short = 'L',
        long = "location",
        global = true,
        help = "Follow redirects"
    )]
    pub location: bool,
    #[arg(
        long = "max-redirects",
        global = true,
        help = "Maximum number of redirects to follow"
    )]
    pub max_redirects: Option<u32>,
}

#[derive(Debug, Args, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TlsOptions {
    #[arg(
        short = 'k',
        long = "insecure",
        global = true,
        help = "Skip TLS verification"
    )]
    pub insecure: bool,
    #[arg(
        long = "cert",
        global = true,
        help = "Client certificate file (PEM format)"
    )]
    pub cert: Option<PathBuf>,
    #[arg(
        long = "key",
        global = true,
        help = "Client certificate key file (PEM format)"
    )]
    pub key: Option<PathBuf>,
    #[arg(
        long = "cacert",
        global = true,
        help = "CA certificate to verify peer against"
    )]
    pub cacert: Option<PathBuf>,
}

#[derive(Debug, Args, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ProxyOptions {
    #[arg(short = 'x', long = "proxy", global = true, help = "Proxy server URL")]
    pub proxy: Option<Url>,
    #[arg(long = "proxy-auth", global = true, help = "Proxy authentication")]
    pub proxy_auth: Option<SecretString>,
}

#[derive(Debug, Args, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OutputOptions {
    #[arg(
        short = 'o',
        long = "output",
        global = true,
        help = "Write output to file instead of stdout"
    )]
    pub output: Option<PathBuf>,

    #[arg(
        short,
        long = "verbose",
        global = true,
        help = "Show detailed request/response info"
    )]
    pub verbose: bool,
    #[arg(
        short,
        long = "simple",
        global = true,
        help = "Show response without color formatting"
    )]
    pub simple: bool,
}

#[derive(Debug, Args, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CompressionOptions {
    #[arg(
        long = "compressed",
        global = true,
        help = "Request compressed response (gzip, deflate, br)"
    )]
    pub compressed: bool,
}

// Merge implementations for combining quest options with CLI options
impl RequestOptions {
    pub fn merge_with(&mut self, cli_options: &RequestOptions) -> Result<&Self> {
        self.authorization.merge_with(&cli_options.authorization)?;
        self.headers.merge_with(&cli_options.headers)?;
        self.params.merge_with(&cli_options.params)?;
        self.body.merge_with(&cli_options.body)?;
        self.timeouts.merge_with(&cli_options.timeouts)?;
        self.redirects.merge_with(&cli_options.redirects)?;
        self.tls.merge_with(&cli_options.tls)?;
        self.proxy.merge_with(&cli_options.proxy)?;
        self.output.merge_with(&cli_options.output)?;
        self.compression.merge_with(&cli_options.compression)?;

        Ok(self)
    }
}

impl AuthOptions {
    pub fn merge_with(&mut self, cli: &AuthOptions) -> Result<&Self> {
        if cli.auth.is_some() {
            self.auth = cli.auth.clone();
        }
        if cli.basic.is_some() {
            self.basic = cli.basic.clone();
        }
        if cli.bearer.is_some() {
            self.bearer = cli.bearer.clone();
        }

        Ok(self)
    }
}

impl HeaderOptions {
    pub fn merge_with(&mut self, cli: &HeaderOptions) -> Result<&Self> {
        // Collections: simple concatenation
        self.header.extend(cli.header.clone());

        // Scalar overrides
        if cli.user_agent.is_some() {
            self.user_agent = cli.user_agent.clone();
        }
        if cli.referer.is_some() {
            self.referer = cli.referer.clone();
        }
        if cli.content_type.is_some() {
            self.content_type = cli.content_type.clone();
        }
        if cli.accept.is_some() {
            self.accept = cli.accept.clone();
        }

        Ok(self)
    }
}

impl ParamOptions {
    pub fn merge_with(&mut self, cli: &ParamOptions) -> Result<&Self> {
        // Use BTreeSet to deduplicate based on entire "key=value" string
        // This allows foo=bar and foo=different to coexist, but deduplicates exact matches
        use std::collections::{BTreeMap, BTreeSet};

        let mut params: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for param in &self.param {
            let (key, value) = param.split_once("=").ok_or_else(|| anyhow::anyhow!(
                "Invalid parameter format: '{}'. Expected format: 'key=value' (must contain an equals sign)",
                param
            ))?;

            params
                .entry(key.trim().to_string())
                .or_default()
                .insert(value.trim().to_string());
        }

        let mut cli_params: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for param in &cli.param {
            let (key, value) = param.split_once("=").ok_or_else(|| anyhow::anyhow!(
                "Invalid parameter format: '{}'. Expected format: 'key=value' (must contain an equals sign)",
                param
            ))?;

            cli_params
                .entry(key.trim().to_string())
                .or_default()
                .insert(value.trim().to_string());
        }

        params.extend(cli_params);

        // Convert back to Vec (sorted order from BTreeSet)
        self.param = params
            .into_iter()
            .flat_map(|(key, values)| {
                values
                    .into_iter()
                    .map(|value| format!("{key}={value}"))
                    .collect::<Vec<_>>()
            })
            .collect();

        Ok(self)
    }
}

impl TimeoutOptions {
    pub fn merge_with(&mut self, cli: &TimeoutOptions) -> Result<&Self> {
        if cli.timeout.is_some() {
            self.timeout = cli.timeout;
        }
        if cli.connect_timeout.is_some() {
            self.connect_timeout = cli.connect_timeout;
        }

        Ok(self)
    }
}

impl RedirectOptions {
    pub fn merge_with(&mut self, cli: &RedirectOptions) -> Result<&Self> {
        if cli.location {
            self.location = cli.location;
        }
        if cli.max_redirects.is_some() {
            self.max_redirects = cli.max_redirects;
        }

        Ok(self)
    }
}

impl TlsOptions {
    pub fn merge_with(&mut self, cli: &TlsOptions) -> Result<&Self> {
        if cli.insecure {
            self.insecure = cli.insecure;
        }
        if cli.cert.is_some() {
            self.cert = cli.cert.clone();
        }
        if cli.key.is_some() {
            self.key = cli.key.clone();
        }
        if cli.cacert.is_some() {
            self.cacert = cli.cacert.clone();
        }

        Ok(self)
    }
}

impl ProxyOptions {
    pub fn merge_with(&mut self, cli: &ProxyOptions) -> Result<&Self> {
        if cli.proxy.is_some() {
            self.proxy = cli.proxy.clone();
        }
        if cli.proxy_auth.is_some() {
            self.proxy_auth = cli.proxy_auth.clone();
        }

        Ok(self)
    }
}

impl OutputOptions {
    pub fn merge_with(&mut self, cli: &OutputOptions) -> Result<&Self> {
        if cli.output.is_some() {
            self.output = cli.output.clone();
        }
        if cli.verbose {
            self.verbose = cli.verbose;
        }
        if cli.simple {
            self.simple = cli.simple;
        }

        Ok(self)
    }
}

impl CompressionOptions {
    pub fn merge_with(&mut self, cli: &CompressionOptions) -> Result<&Self> {
        if cli.compressed {
            self.compressed = cli.compressed;
        }

        Ok(self)
    }
}

impl BodyOptions {
    pub fn merge_with(&mut self, cli: &BodyOptions) -> Result<&Self> {
        // Body options are mutually exclusive (clap group)
        // If CLI provides any body option, it completely replaces quest body
        if cli.json.is_some() | !cli.form.is_empty() | cli.raw.is_some() | cli.binary.is_some() {
            *self = cli.clone();
        }

        // If CLI has no body options, keep quest body unchanged
        Ok(self)
    }
}
