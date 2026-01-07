# Quest

An HTTP client CLI for all your fetch (re)quests. Quest combines the simplicity of direct terminal commands with the power of reusable, templated request configurations.

## Features

- Direct HTTP requests from the command line
- Reusable request templates in YAML quest files
- Environment variable support with default values
- Composable URLs with base_url and path
- YAML anchors and merge keys for DRY configurations

## Installation

```sh
cargo install quest-cli
```

Or from source:

```sh
cargo install --git https://github.com/theelderbeever/quest-cli
```

## Quick Start

### Direct Requests

Make HTTP requests directly from the command line:

```sh
# Simple GET request
quest get https://api.example.com/users

# POST with JSON body
quest post https://api.example.com/users --json '{"name": "John"}'

# With authentication
quest get https://api.example.com/protected --bearer YOUR_TOKEN

# With query parameters
quest get https://api.example.com/users --param status=active --param role=admin

# Multiple options
quest post https://api.example.com/users \
  --bearer TOKEN \
  --header "X-Custom: value" \
  --json '{"name": "Jane"}' \
  --timeout 30s
```

### Quest Files

Define reusable requests in a `.quests.yaml` file:

```yaml
# Define reusable defaults with YAML anchors
x-api-defaults: &api-defaults
  base_url: https://api.example.com
  bearer: "${API_TOKEN}"
  accept: application/json
  timeout: 30s

quests:
  get-user:
    <<: *api-defaults
    method: get
    path: /users/1

  list-users:
    <<: *api-defaults
    method: get
    path: /users
    params:
      - status=active
      - limit=10

  create-user:
    <<: *api-defaults
    method: post
    path: /users
    json: '{"name": "John Doe", "email": "john@example.com"}'
```

Execute named quests:

```sh
# List all available quests
quest list

# Run a quest from the file
quest go get-user

# Override quest file settings from CLI
quest go get-user --bearer DIFFERENT_TOKEN

# Use a different quest file
quest list -f my-quests.yaml
quest go -f my-quests.yaml create-user
```

## Usage

### HTTP Methods

Quest supports all standard HTTP methods:

```sh
quest get <URL>
quest post <URL>
quest put <URL>
quest patch <URL>
quest delete <URL>
```

### Authentication

**Bearer Token:**
```sh
quest get https://api.example.com/data --bearer YOUR_TOKEN
```

**Basic Auth:**
```sh
quest get https://api.example.com/data --auth username:password
quest get https://api.example.com/data --basic username:password
```

**Custom Headers:**
```sh
quest get https://api.example.com/data -H "Authorization: Custom token"
```

### Query Parameters

Add query parameters to your requests:

```sh
# Single parameter
quest get https://api.example.com/users --param name=John

# Multiple parameters (short form)
quest get https://api.example.com/users -p status=active -p page=1 -p limit=20
```

In quest files:
```yaml
quests:
  search:
    method: get
    url: https://api.example.com/search
    param:  # or use "params" as alias
      - q=rust
      - type=repository
      - sort=stars
```

### Request Body

**JSON Body:**
```sh
# Inline JSON
quest post https://api.example.com/users --json '{"name": "John", "age": 30}'

# From file
quest post https://api.example.com/users --json @data.json
```

**Form Data:**
```sh
quest post https://api.example.com/upload \
  --form "name=John" \
  --form "email=john@example.com" \
  --form "file=@photo.jpg"
```

**Raw/Binary Data:**
```sh
quest post https://api.example.com/data --raw "plain text data"
quest post https://api.example.com/upload --binary @file.bin
```

### Headers

**Custom Headers:**
```sh
quest get https://api.example.com/data \
  -H "X-Custom-Header: value" \
  -H "X-Another: another-value"
```

**Common Headers:**
```sh
quest get https://api.example.com/data \
  --user-agent "MyApp/1.0" \
  --accept "application/json" \
  --content-type "application/json" \
  --referer "https://example.com"
```

### Composable URLs

Instead of repeating full URLs, use `base_url` with `path`:

```yaml
x-defaults: &defaults
  base_url: https://api.example.com
  bearer: "${API_TOKEN}"

quests:
  get-users:
    <<: *defaults
    method: get
    path: /users  # Results in: https://api.example.com/users

  get-user:
    <<: *defaults
    method: get
    path: /users/1  # Results in: https://api.example.com/users/1
```

You can also use a direct `url` field if preferred:
```yaml
quests:
  get-user:
    method: get
    url: https://api.example.com/users/1
```

### Environment Variables

Quest supports shell-style environment variable expansion with default values:

```yaml
quests:
  api-call:
    method: get
    url: ${API_URL:-https://api.example.com}/users
    bearer: "${API_TOKEN}"
    timeout: ${TIMEOUT:-30s}
```

Load environment variables from a file:
```sh
# Default: .env
quest go api-call

# Custom env file
quest -e .env.production go api-call
```

### Timeouts

**Request Timeout:**
```sh
quest get https://api.example.com/data --timeout 30s
quest get https://api.example.com/data -t 5m
```

**Connection Timeout:**
```sh
quest get https://api.example.com/data --connect-timeout 10s
```

Supported time units: `s` (seconds), `m` (minutes), `h` (hours), `ms` (milliseconds)

### Redirects

**Follow Redirects:**
```sh
quest get https://example.com/redirect -L
quest get https://example.com/redirect --location --max-redirects 5
```

### TLS/SSL

**Skip Certificate Verification:**
```sh
quest get https://self-signed.example.com -k
quest get https://self-signed.example.com --insecure
```

**Client Certificates:**
```sh
quest get https://api.example.com/data \
  --cert client.crt \
  --key client.key
```

**Custom CA Certificate:**
```sh
quest get https://api.example.com/data --cacert ca.crt
```

### Proxy

**HTTP/HTTPS Proxy:**
```sh
quest get https://api.example.com/data --proxy http://proxy.example.com:8080
quest get https://api.example.com/data -x http://user:pass@proxy.example.com:8080
```

**Proxy Authentication:**
```sh
quest get https://api.example.com/data \
  --proxy http://proxy.example.com:8080 \
  --proxy-auth username:password
```

### Output Options

**Save to File:**
```sh
quest get https://api.example.com/data -o response.json
quest get https://api.example.com/data --output response.json
```

**Include Response Headers:**
```sh
quest get https://api.example.com/data -i
quest get https://api.example.com/data --include
```

**Request Compressed Response:**
```sh
quest get https://api.example.com/data --compressed
```

**Simple Output (no color):**
```sh
quest get https://api.example.com/data --simple
```

**Verbose Output:**
```sh
quest get https://api.example.com/data -v
quest get https://api.example.com/data --verbose
```

## Quest File Reference

### Complete Example

```yaml
# Define reusable configurations with YAML anchors
x-api-defaults: &api-defaults
  base_url: https://api.example.com
  bearer: "${API_TOKEN}"
  accept: application/json
  timeout: 30s

x-test-defaults: &test-defaults
  base_url: https://httpbin.org
  timeout: 10s

quests:
  # Simple GET request
  get-user:
    <<: *api-defaults
    method: get
    path: /users/1

  # GET with query parameters
  search-users:
    <<: *api-defaults
    method: get
    path: /users
    params:
      - status=active
      - role=admin
      - limit=50

  # POST with JSON body
  create-user:
    <<: *api-defaults
    method: post
    path: /users
    json: |
      {
        "name": "John Doe",
        "email": "john@example.com",
        "role": "user"
      }

  # POST with form data
  upload-file:
    <<: *api-defaults
    method: post
    path: /upload
    form:
      - name=document
      - file=@document.pdf
      - description=Important file

  # Request with custom headers
  custom-request:
    <<: *api-defaults
    method: get
    path: /data
    header:
      - "X-Custom-Header: custom-value"
      - "X-Request-ID: ${REQUEST_ID}"

  # Using httpbin for testing
  test-post:
    <<: *test-defaults
    method: post
    path: /post
    json: '{"test": "data"}'
    param:
      - foo=bar
```

### Field Reference

**URL Configuration:**
- `url`: Full URL (mutually exclusive with base_url/path)
- `base_url`: Base URL to combine with path
- `path`: Path to append to base_url

**Request Configuration:**
- `method`: HTTP method (get, post, put, patch, delete)
- `bearer`: Bearer token authentication
- `basic`: Basic authentication (user:pass format)
- `auth`: Alias for basic authentication

**Query Parameters:**
- `param`: List of query parameters (key=value format)
- `params`: Alias for param

**Headers:**
- `header`: List of custom headers (key:value format)
- `user_agent`: User-Agent header
- `accept`: Accept header
- `content_type`: Content-Type header
- `referer`: Referer header

**Body:**
- `json`: JSON body (string or @file)
- `form`: Form data (list of key=value)
- `raw`: Raw body data
- `binary`: Binary body data

**Timeouts:**
- `timeout`: Overall request timeout (e.g., "30s", "1m")
- `connect_timeout`: Connection timeout

**Redirects:**
- `location`: Follow redirects (boolean)
- `max_redirects`: Maximum redirects to follow

**TLS:**
- `insecure`: Skip TLS verification (boolean)
- `cert`: Client certificate file
- `key`: Client certificate key file
- `cacert`: CA certificate file

**Proxy:**
- `proxy`: Proxy server URL
- `proxy_auth`: Proxy authentication (user:pass format)

**Output:**
- `output`: Output file path
- `include`: Include response headers (boolean)
- `compressed`: Request compressed response (boolean)
- `simple`: Simple output without color (boolean)
- `verbose`: Verbose output (boolean)

## Examples

See the [`.quests.yaml`](.quests.yaml) file for comprehensive examples of all features.

## Environment Variables

Quest loads environment variables from `.env` by default, or from a file specified with `-e`:

```sh
# Use default .env
quest go my-quest

# Use custom env file
quest -e .env.production go my-quest

# Use .env.local
quest -e .env.local go my-quest
```

Environment variables can include default values using shell syntax:
```
${VAR:-default_value}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
