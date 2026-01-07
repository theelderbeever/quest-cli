use anyhow::Result;
use reqwest::blocking::{Client, ClientBuilder, RequestBuilder, Response};
use secrecy::ExposeSecret;

use crate::cli::{
    AuthOptions, BodyOptions, CompressionOptions, HeaderOptions, ParamOptions, ProxyOptions,
    RedirectOptions, RequestOptions, TimeoutOptions, TlsOptions,
};

// Generic trait for applying options to builders
pub trait ApplyOptions<T> {
    fn apply(&self, builder: T) -> Result<T>;
}

// Wrapper for ClientBuilder with Quest-specific options
#[derive(Debug)]
pub struct QuestClientBuilder(ClientBuilder);

impl QuestClientBuilder {
    pub fn new() -> Self {
        Self(ClientBuilder::new())
    }

    pub fn apply<O: ApplyOptions<ClientBuilder>>(mut self, options: &O) -> Result<Self> {
        self.0 = options.apply(self.0)?;
        Ok(self)
    }

    pub fn build(self) -> Result<Client> {
        Ok(self.0.build()?)
    }
}

impl Default for QuestClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Wrapper for RequestBuilder with Quest-specific options
#[derive(Debug)]
pub struct QuestRequestBuilder(RequestBuilder);

impl QuestRequestBuilder {
    pub fn from_request(inner: RequestBuilder) -> Self {
        Self(inner)
    }

    pub fn apply<O: ApplyOptions<RequestBuilder>>(mut self, options: &O) -> Result<Self> {
        self.0 = options.apply(self.0)?;
        Ok(self)
    }

    pub fn send(self) -> Result<Response> {
        Ok(self.0.send()?)
    }
}

impl ApplyOptions<RequestBuilder> for AuthOptions {
    fn apply(&self, mut builder: RequestBuilder) -> Result<RequestBuilder> {
        // Handle --auth (user:pass format)
        if let Some(auth) = &self.auth {
            let auth_str = auth.expose_secret();
            let (user, pass) = auth_str.split_once(':')
                .ok_or_else(|| anyhow::anyhow!(
                    "Invalid auth format. Expected format: 'username:password' (must contain a colon)"
                ))?;

            if user.is_empty() {
                anyhow::bail!("Invalid auth format. Username cannot be empty");
            }

            builder = builder.basic_auth(user, Some(pass));
        }

        // Handle --basic (user:pass format)
        if let Some(basic) = &self.basic {
            let basic_str = basic.expose_secret();
            let (user, pass) = basic_str.split_once(':')
                .ok_or_else(|| anyhow::anyhow!(
                    "Invalid basic auth format. Expected format: 'username:password' (must contain a colon)"
                ))?;

            if user.is_empty() {
                anyhow::bail!("Invalid basic auth format. Username cannot be empty");
            }

            builder = builder.basic_auth(user, Some(pass));
        }

        // Handle --bearer
        if let Some(bearer) = &self.bearer {
            builder = builder.bearer_auth(bearer.expose_secret());
        }

        Ok(builder)
    }
}

impl ApplyOptions<RequestBuilder> for HeaderOptions {
    fn apply(&self, mut builder: RequestBuilder) -> Result<RequestBuilder> {
        // Add custom headers
        for header in &self.header {
            let (key, value) = header.split_once(':')
                .ok_or_else(|| anyhow::anyhow!(
                    "Invalid header format: '{}'. Expected format: 'Key: Value' (must contain a colon)",
                    header
                ))?;

            let key = key.trim();
            let value = value.trim();

            if key.is_empty() {
                anyhow::bail!("Invalid header: '{}'. Header name cannot be empty", header);
            }

            builder = builder.header(key, value);
        }

        // Add specific headers
        let user_agent = self.user_agent.as_deref().unwrap_or("quest/0.1.0");
        builder = builder.header("User-Agent", user_agent);
        if let Some(referer) = &self.referer {
            builder = builder.header("Referer", referer);
        }
        if let Some(ct) = &self.content_type {
            builder = builder.header("Content-Type", ct);
        }
        if let Some(accept) = &self.accept {
            builder = builder.header("Accept", accept);
        }

        Ok(builder)
    }
}

impl ApplyOptions<RequestBuilder> for ParamOptions {
    fn apply(&self, builder: RequestBuilder) -> Result<RequestBuilder> {
        let mut params: Vec<(&str, &str)> = Vec::new();

        for param in &self.param {
            let (key, value) = param.split_once('=')
                .ok_or_else(|| anyhow::anyhow!(
                    "Invalid parameter format: '{}'. Expected format: 'key=value' (must contain an equals sign)",
                    param
                ))?;

            let key = key.trim();
            let value = value.trim();

            if key.is_empty() {
                anyhow::bail!(
                    "Invalid parameter: '{}'. Parameter name cannot be empty",
                    param
                );
            }

            params.push((key, value));
        }

        Ok(builder.query(&params))
    }
}

impl ApplyOptions<RequestBuilder> for TimeoutOptions {
    fn apply(&self, mut builder: RequestBuilder) -> Result<RequestBuilder> {
        if let Some(timeout) = &self.timeout {
            let duration: std::time::Duration = (*timeout).into();
            builder = builder.timeout(duration);
        }
        // Note: connect_timeout is set on the Client, not RequestBuilder
        // This will need to be applied when building the client
        Ok(builder)
    }
}

impl ApplyOptions<RequestBuilder> for BodyOptions {
    fn apply(&self, builder: RequestBuilder) -> Result<RequestBuilder> {
        // Handle JSON body
        if let Some(json) = &self.json {
            let data = json.resolve()?;
            return Ok(builder
                .body(data)
                .header("Content-Type", "application/json"));
        }

        // Handle form data
        if !self.form.is_empty() {
            let mut form = reqwest::blocking::multipart::Form::new();
            for field in &self.form {
                let value = field.value.resolve()?;
                form = form.text(
                    field.name.clone(),
                    String::from_utf8_lossy(&value).to_string(),
                );
            }
            return Ok(builder.multipart(form));
        }

        // Handle raw data
        if let Some(raw) = &self.raw {
            let data = raw.resolve()?;
            return Ok(builder.body(data));
        }

        // Handle binary data
        if let Some(binary) = &self.binary {
            let data = binary.resolve()?;
            return Ok(builder
                .body(data)
                .header("Content-Type", "application/octet-stream"));
        }

        Ok(builder)
    }
}

impl ApplyOptions<RequestBuilder> for CompressionOptions {
    fn apply(&self, mut builder: RequestBuilder) -> Result<RequestBuilder> {
        if self.compressed {
            // Request compressed response (gzip, deflate, br)
            builder = builder.header("Accept-Encoding", "gzip, deflate, br");
        }
        Ok(builder)
    }
}

impl ApplyOptions<RequestBuilder> for RequestOptions {
    fn apply(&self, builder: RequestBuilder) -> Result<RequestBuilder> {
        let builder = self.authorization.apply(builder)?;
        let builder = self.headers.apply(builder)?;
        let builder = self.params.apply(builder)?;
        let builder = self.timeouts.apply(builder)?;
        self.compression.apply(builder)
    }
}

impl ApplyOptions<ClientBuilder> for TimeoutOptions {
    fn apply(&self, mut builder: ClientBuilder) -> Result<ClientBuilder> {
        if let Some(timeout) = &self.timeout {
            let duration: std::time::Duration = (*timeout).into();
            builder = builder.timeout(duration);
        }
        if let Some(connect_timeout) = &self.connect_timeout {
            let duration: std::time::Duration = (*connect_timeout).into();
            builder = builder.connect_timeout(duration);
        }
        Ok(builder)
    }
}

impl ApplyOptions<ClientBuilder> for RedirectOptions {
    fn apply(&self, mut builder: ClientBuilder) -> Result<ClientBuilder> {
        if self.location {
            // Follow redirects (enabled by default in reqwest)
            if let Some(max) = self.max_redirects {
                builder = builder.redirect(reqwest::redirect::Policy::limited(max as usize));
            }
        } else {
            // Disable redirects
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }
        Ok(builder)
    }
}

impl ApplyOptions<ClientBuilder> for TlsOptions {
    fn apply(&self, mut builder: ClientBuilder) -> Result<ClientBuilder> {
        if self.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }

        // Add client certificate if provided (both cert and key required)
        if let (Some(cert_path), Some(key_path)) = (&self.cert, &self.key) {
            let cert_pem = std::fs::read(cert_path)?;
            let key_pem = std::fs::read(key_path)?;

            // Concatenate cert and key PEM data
            let mut pem_data = cert_pem;
            pem_data.extend_from_slice(&key_pem);

            let identity = reqwest::Identity::from_pem(&pem_data)?;
            builder = builder.identity(identity);
        }

        // Add CA certificate if provided
        if let Some(cacert_path) = &self.cacert {
            let cacert_bytes = std::fs::read(cacert_path)?;
            let cert = reqwest::Certificate::from_pem(&cacert_bytes)?;
            builder = builder.add_root_certificate(cert);
        }

        Ok(builder)
    }
}

impl ApplyOptions<ClientBuilder> for ProxyOptions {
    fn apply(&self, mut builder: ClientBuilder) -> Result<ClientBuilder> {
        if let Some(proxy_url) = &self.proxy {
            let mut proxy = reqwest::Proxy::all(proxy_url.as_str())?;

            // Add proxy authentication if provided
            if let Some(auth) = &self.proxy_auth {
                let auth_str = auth.expose_secret();
                let (user, pass) = auth_str.split_once(':')
                    .ok_or_else(|| anyhow::anyhow!(
                        "Invalid proxy auth format. Expected format: 'username:password' (must contain a colon)"
                    ))?;

                if user.is_empty() {
                    anyhow::bail!("Invalid proxy auth format. Username cannot be empty");
                }

                proxy = proxy.basic_auth(user, pass);
            }

            builder = builder.proxy(proxy);
        }

        Ok(builder)
    }
}

impl ApplyOptions<ClientBuilder> for RequestOptions {
    fn apply(&self, builder: ClientBuilder) -> Result<ClientBuilder> {
        let builder = self.timeouts.apply(builder)?;
        let builder = self.redirects.apply(builder)?;
        let builder = self.tls.apply(builder)?;
        self.proxy.apply(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{AuthOptions, HeaderOptions, ParamOptions, ProxyOptions};
    use secrecy::SecretString;

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_string().into_boxed_str())
    }

    // Validation tests

    #[test]
    fn test_header_missing_colon_returns_error() {
        let headers = HeaderOptions {
            header: vec!["InvalidHeaderFormat".to_string()],
            ..Default::default()
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        let result = builder.apply(&headers);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must contain a colon")
        );
    }

    #[test]
    fn test_header_empty_key_returns_error() {
        let headers = HeaderOptions {
            header: vec![": value".to_string()],
            ..Default::default()
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        let result = builder.apply(&headers);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Header name cannot be empty")
        );
    }

    #[test]
    fn test_header_empty_value_is_allowed() {
        let headers = HeaderOptions {
            header: vec!["X-Custom:".to_string()],
            ..Default::default()
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        assert!(builder.apply(&headers).is_ok());
    }

    #[test]
    fn test_parameter_missing_equals_returns_error() {
        let params = ParamOptions {
            param: vec!["invalid".to_string()],
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        let result = builder.apply(&params);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must contain an equals sign")
        );
    }

    #[test]
    fn test_parameter_empty_key_returns_error() {
        let params = ParamOptions {
            param: vec!["=value".to_string()],
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        let result = builder.apply(&params);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Parameter name cannot be empty")
        );
    }

    #[test]
    fn test_parameter_empty_value_is_allowed() {
        let params = ParamOptions {
            param: vec!["key=".to_string()],
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        assert!(builder.apply(&params).is_ok());
    }

    #[test]
    fn test_auth_missing_colon_returns_error() {
        let auth = AuthOptions {
            auth: Some(secret("invalid")),
            ..Default::default()
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        let result = builder.apply(&auth);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must contain a colon")
        );
    }

    #[test]
    fn test_auth_empty_username_returns_error() {
        let auth = AuthOptions {
            auth: Some(secret(":password")),
            ..Default::default()
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        let result = builder.apply(&auth);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Username cannot be empty")
        );
    }

    #[test]
    fn test_auth_empty_password_is_allowed() {
        let auth = AuthOptions {
            auth: Some(secret("user:")),
            ..Default::default()
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        assert!(builder.apply(&auth).is_ok());
    }

    #[test]
    fn test_proxy_auth_validation() {
        let proxy_opts = ProxyOptions {
            proxy: Some(url::Url::parse("http://proxy.example.com:8080").unwrap()),
            proxy_auth: Some(secret("invalid")),
        };

        let builder = QuestClientBuilder::new();
        let result = builder.apply(&proxy_opts);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must contain a colon")
        );
    }

    #[test]
    fn test_whitespace_trimming_in_headers() {
        let headers = HeaderOptions {
            header: vec!["  X-Custom  :  value  ".to_string()],
            ..Default::default()
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        assert!(builder.apply(&headers).is_ok());
    }

    #[test]
    fn test_whitespace_trimming_results_in_empty_key() {
        let headers = HeaderOptions {
            header: vec!["   : value".to_string()],
            ..Default::default()
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        assert!(builder.apply(&headers).is_err());
    }

    // Option application tests

    #[test]
    fn test_apply_all_header_types() {
        let headers = HeaderOptions {
            header: vec!["X-Custom: value".to_string()],
            user_agent: Some("TestAgent/1.0".to_string()),
            referer: Some("https://example.com".to_string()),
            content_type: Some("application/json".to_string()),
            accept: Some("application/json".to_string()),
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        assert!(builder.apply(&headers).is_ok());
    }

    #[test]
    fn test_apply_bearer_auth() {
        let auth = AuthOptions {
            bearer: Some(secret("token123")),
            ..Default::default()
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        assert!(builder.apply(&auth).is_ok());
    }

    #[test]
    fn test_apply_multiple_params() {
        let params = ParamOptions {
            param: vec!["foo=bar".to_string(), "baz=qux".to_string()],
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let builder = QuestRequestBuilder::from_request(request);

        assert!(builder.apply(&params).is_ok());
    }

    #[test]
    fn test_options_apply_in_sequence() {
        let auth = AuthOptions {
            basic: Some(secret("user:pass")),
            ..Default::default()
        };
        let headers = HeaderOptions {
            header: vec!["X-Custom: value".to_string()],
            ..Default::default()
        };
        let params = ParamOptions {
            param: vec!["key=value".to_string()],
        };

        let client = ClientBuilder::new().build().unwrap();
        let request = client.get("https://example.com");
        let mut builder = QuestRequestBuilder::from_request(request);

        builder = builder.apply(&auth).unwrap();
        builder = builder.apply(&headers).unwrap();
        let _ = builder.apply(&params).unwrap();

        // If we got here, all options applied successfully
    }
}
