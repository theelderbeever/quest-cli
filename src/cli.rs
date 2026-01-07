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
                let mut quest_command = quest_file
                    .get(&name)
                    .ok_or_else(|| anyhow::anyhow!("Quest '{}' not found.", name))?
                    .clone();

                // 3. Merge with CLI options (CLI overrides quest)
                match &mut quest_command {
                    QuestCommand::Get { options: qopts, .. }
                    | QuestCommand::Delete { options: qopts, .. } => {
                        qopts.merge_with(&options);
                    }
                    QuestCommand::Post { options: qopts, .. }
                    | QuestCommand::Put { options: qopts, .. }
                    | QuestCommand::Patch { options: qopts, .. } => {
                        qopts.merge_with(&options);
                    }
                }

                // 4. Execute the quest command
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
            Command::Post { url, body } => {
                let quest = QuestCommand::Post {
                    url_spec: QuestUrl::Direct { url },
                    body,
                    options: RequestOptions::default(),
                };
                Self::execute_quest_command(options, quest)
            }
            Command::Put { url, body } => {
                let quest = QuestCommand::Put {
                    url_spec: QuestUrl::Direct { url },
                    body,
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
            Command::Patch { url, body } => {
                let quest = QuestCommand::Patch {
                    url_spec: QuestUrl::Direct { url },
                    body,
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
        // 1. Extract quest file options and merge with CLI options
        let mut quest_options = match &quest {
            QuestCommand::Get { options, .. } => options,
            QuestCommand::Post { options, .. } => options,
            QuestCommand::Put { options, .. } => options,
            QuestCommand::Delete { options, .. } => options,
            QuestCommand::Patch { options, .. } => options,
        }
        .clone();
        quest_options.merge_with(&cli_options);

        // 2. Build the client with merged options
        let client = QuestClientBuilder::new().apply(&quest_options)?.build()?;

        // 3. Build the request based on the quest command and capture details for verbose output
        let (request_builder, body_options, method, url) = match &quest {
            QuestCommand::Get { url_spec, .. } => {
                let url = url_spec.to_url()?;
                (client.get(url.as_str()), None, "GET", url)
            }
            QuestCommand::Post { url_spec, body, .. } => {
                let url = url_spec.to_url()?;
                (client.post(url.as_str()), Some(body.clone()), "POST", url)
            }
            QuestCommand::Put { url_spec, body, .. } => {
                let url = url_spec.to_url()?;
                (client.put(url.as_str()), Some(body.clone()), "PUT", url)
            }
            QuestCommand::Delete { url_spec, .. } => {
                let url = url_spec.to_url()?;
                (client.delete(url.as_str()), None, "DELETE", url)
            }
            QuestCommand::Patch { url_spec, body, .. } => {
                let url = url_spec.to_url()?;
                (client.patch(url.as_str()), Some(body.clone()), "PATCH", url)
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

        // 4. Apply request options (use merged options)
        let mut request =
            QuestRequestBuilder::from_request(request_builder).apply(&quest_options)?;

        // 5. Apply body options if present
        if let Some(body) = body_options {
            request = request.apply(&body)?;
        }

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

        // Prepare output content
        let mut output_parts = Vec::new();

        // Include headers if requested
        if output_opts.include {
            let status_line = format!(
                "HTTP/1.1 {} {}\n",
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or("")
            );
            output_parts.push(status_line);

            for (name, value) in response.headers() {
                if let Ok(val_str) = value.to_str() {
                    output_parts.push(format!("{}: {}\n", name, val_str));
                }
            }
            output_parts.push("\n".to_string());
        }

        if output_opts.verbose {
            Self::log_response_verbose(&response)?;
        }

        // Get response body
        let body_text = if response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("application/json") || ct.contains("application/vnd.api+json"))
            .unwrap_or(false)
            && !output_opts.simple
        {
            // Parse as JSON and pretty-print with colors
            let json_value = response.json::<serde_json::Value>()?;
            colored_json::to_colored_json_auto(&json_value)?
        } else {
            // Not JSON or unknown content-type, just get as text
            response.text()?
        };

        output_parts.push(body_text);

        let full_output = output_parts.join("");

        // Write to file or stdout
        if let Some(output_file) = &output_opts.output {
            let mut file = std::fs::File::create(output_file).with_context(|| {
                format!("Failed to create output file: {}", output_file.display())
            })?;
            file.write_all(full_output.as_bytes())?;
        } else {
            println!("{full_output}");
        }

        Ok(())
    }
}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    Get {
        url: Url,
    },
    Post {
        url: Url,
        #[clap(flatten)]
        body: BodyOptions,
    },
    Put {
        url: Url,
        #[clap(flatten)]
        body: BodyOptions,
    },
    Delete {
        url: Url,
    },
    Patch {
        url: Url,
        #[clap(flatten)]
        body: BodyOptions,
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
        help = "Send data as JSON (auto sets Content-Type)",
        value_hint = clap::ValueHint::FilePath
    )]
    pub json: Option<StringOrFile>,
    #[arg(
        short = 'F',
        long = "form",
        group = "body",
        help = "Form data (repeatable)"
    )]
    pub form: Vec<FormField>,
    #[arg(
        long = "raw",
        group = "body",
        help = "Send raw data without processing",
        value_hint = clap::ValueHint::FilePath
    )]
    pub raw: Option<StringOrFile>,
    #[arg(
        long = "binary",
        group = "body",
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
        short = 'i',
        long = "include",
        global = true,
        help = "Include response headers in output"
    )]
    pub include: bool,
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
    pub fn merge_with(&mut self, cli_options: &RequestOptions) {
        self.authorization.merge_with(&cli_options.authorization);
        self.headers.merge_with(&cli_options.headers);
        self.params.merge_with(&cli_options.params);
        self.timeouts.merge_with(&cli_options.timeouts);
        self.redirects.merge_with(&cli_options.redirects);
        self.tls.merge_with(&cli_options.tls);
        self.proxy.merge_with(&cli_options.proxy);
        self.output.merge_with(&cli_options.output);
        self.compression.merge_with(&cli_options.compression);
    }
}

impl AuthOptions {
    pub fn merge_with(&mut self, cli: &AuthOptions) {
        if cli.auth.is_some() {
            self.auth = cli.auth.clone();
        }
        if cli.basic.is_some() {
            self.basic = cli.basic.clone();
        }
        if cli.bearer.is_some() {
            self.bearer = cli.bearer.clone();
        }
    }
}

impl HeaderOptions {
    pub fn merge_with(&mut self, cli: &HeaderOptions) {
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
    }
}

impl ParamOptions {
    pub fn merge_with(&mut self, cli: &ParamOptions) {
        // Concatenate parameters
        self.param.extend(cli.param.clone());
    }
}

impl TimeoutOptions {
    pub fn merge_with(&mut self, cli: &TimeoutOptions) {
        if cli.timeout.is_some() {
            self.timeout = cli.timeout;
        }
        if cli.connect_timeout.is_some() {
            self.connect_timeout = cli.connect_timeout;
        }
    }
}

impl RedirectOptions {
    pub fn merge_with(&mut self, cli: &RedirectOptions) {
        if cli.location {
            self.location = cli.location;
        }
        if cli.max_redirects.is_some() {
            self.max_redirects = cli.max_redirects;
        }
    }
}

impl TlsOptions {
    pub fn merge_with(&mut self, cli: &TlsOptions) {
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
    }
}

impl ProxyOptions {
    pub fn merge_with(&mut self, cli: &ProxyOptions) {
        if cli.proxy.is_some() {
            self.proxy = cli.proxy.clone();
        }
        if cli.proxy_auth.is_some() {
            self.proxy_auth = cli.proxy_auth.clone();
        }
    }
}

impl OutputOptions {
    pub fn merge_with(&mut self, cli: &OutputOptions) {
        if cli.output.is_some() {
            self.output = cli.output.clone();
        }
        if cli.include {
            self.include = cli.include;
        }
        if cli.verbose {
            self.verbose = cli.verbose;
        }
        if cli.simple {
            self.simple = cli.simple;
        }
    }
}

impl CompressionOptions {
    pub fn merge_with(&mut self, cli: &CompressionOptions) {
        if cli.compressed {
            self.compressed = cli.compressed;
        }
    }
}
