# Simple Spotify Authentication Tool

A Rust command-line tool for obtaining Spotify API authentication tokens.

## Features

- Authenticate against Spotify Web API
- Uses Authorization Code flow with PKCE
- Automatically opens browser for authentication
- Local HTTP server to handle the OAuth callback
- Configurable via JSON config file

## Usage

1. First, set up a Spotify Developer application at [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
2. Create a config JSON file with your app credentials:

```json
{
  "client_id": "your_spotify_client_id",
  "client_secret": "your_spotify_client_secret",
  "redirect_uri": "http://localhost:8888/callback",
  "scopes": ["user-read-private", "user-read-email", "playlist-read-private"],
  "port": 8888
}
```

3. Run the tool:

```bash
cargo run -- --config-file config.json
```

## Required Environment Variables

None - all configuration is done through the config file.

## Development

This project uses the following dependencies:

- reqwest - HTTP client
- tokio - Async runtime
- serde - Serialization/deserialization
- clap - Command-line argument parsing
- tiny_http - Lightweight HTTP server
- and more...

## License

MIT
