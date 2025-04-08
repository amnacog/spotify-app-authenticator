use crate::config::Config;
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use rand::{thread_rng, Rng};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, Server};
use url::Url;
use webbrowser;

// Code verifier length in characters (not bytes) as per PKCE spec
// The spec recommends between 43-128 characters
const CODE_VERIFIER_LENGTH: usize = 64;

/// Represents the Spotify access tokens returned after successful authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct SpotifyTokens {
    /// The access token for making Spotify API requests
    pub access_token: String,
    /// The token used to refresh the access token when it expires
    pub refresh_token: String,
    /// The number of seconds until the access token expires
    pub expires_in: u64,
    /// The type of token (usually "Bearer")
    pub token_type: String,
    /// The scope of access granted
    pub scope: String,
}

/// Handles the Spotify authentication flow
pub struct SpotifyAuthenticator {
    config: Config,
    http_client: Client,
    use_pkce: bool,
}

impl SpotifyAuthenticator {
    /// Create a new SpotifyAuthenticator with the given config
    pub fn new(config: Config, use_pkce: bool) -> Self {
        Self {
            config,
            http_client: Client::new(),
            use_pkce,
        }
    }

    /// Generate a random code verifier string for PKCE
    fn generate_code_verifier() -> String {
        // PKCE code verifier should be a random string of 43-128 characters
        // Contains only alphanumeric characters plus '-', '.', '_', '~'
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        let mut rng = thread_rng();

        // Generate a random string of the specified length
        (0..CODE_VERIFIER_LENGTH)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Generate code challenge from code verifier for PKCE
    fn generate_code_challenge(code_verifier: &str) -> String {
        // Create a SHA256 digest of the code verifier
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let hash = hasher.finalize();

        // Encode to URL-safe base64 and remove padding
        general_purpose::URL_SAFE_NO_PAD.encode(hash)
    }

    /// Start the Spotify authorization flow
    pub fn authenticate(&self) -> Result<SpotifyTokens> {
        let (code_verifier, code_challenge) = if self.use_pkce {
            // Generate PKCE code verifier and challenge
            let code_verifier = Self::generate_code_verifier();
            println!(
                "Generated code verifier: {} (length: {})",
                code_verifier,
                code_verifier.len()
            );

            let code_challenge = Self::generate_code_challenge(&code_verifier);
            println!("Generated code challenge: {}", code_challenge);
            (Some(code_verifier), Some(code_challenge))
        } else {
            (None, None)
        };

        // Create a shared state to hold the authorization code we'll receive
        let auth_code = Arc::new(Mutex::new(None::<String>));

        // Start local HTTP server to receive the callback
        let server = self.start_callback_server()?;

        // Build the authorization URL
        let auth_url = self.build_authorization_url(code_challenge.as_deref())?;

        // Open the user's browser to the authorization URL
        println!("Opening browser for Spotify authentication...");
        println!("If the browser doesn't open automatically, please visit:");
        println!("{}", auth_url);

        webbrowser::open(&auth_url)?;

        // Wait for the auth code from the callback
        let authorization_code = self.wait_for_callback(server, auth_code)?;

        // Exchange the authorization code for tokens
        self.exchange_code_for_tokens(&authorization_code, code_verifier.as_deref())
    }

    /// Build the Spotify authorization URL
    fn build_authorization_url(&self, code_challenge: Option<&str>) -> Result<String> {
        let mut url = Url::parse("https://accounts.spotify.com/authorize")?;

        let mut query_pairs = url.query_pairs_mut();
        query_pairs
            .append_pair("client_id", &self.config.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &self.config.scopes_string());

        if self.use_pkce {
            if let Some(challenge) = code_challenge {
                query_pairs
                    .append_pair("code_challenge_method", "S256")
                    .append_pair("code_challenge", challenge);
            }
        }

        drop(query_pairs); // Release the mutable borrow
        Ok(url.to_string())
    }

    /// Start a local HTTP server to handle the OAuth callback
    fn start_callback_server(&self) -> Result<Server> {
        let server_addr = format!("127.0.0.1:{}", self.config.port);
        let server = Server::http(&server_addr)
            .map_err(|e| anyhow::anyhow!("Failed to start HTTP server: {}", e))?;

        println!("Callback server listening on {}", server_addr);

        Ok(server)
    }

    /// Wait for the callback from Spotify with the authorization code
    fn wait_for_callback(
        &self,
        server: Server,
        auth_code: Arc<Mutex<Option<String>>>,
    ) -> Result<String> {
        println!("Waiting for Spotify callback...");

        // Handle incoming requests until we get the auth code
        for request in server.incoming_requests() {
            if let Some(code) = self.handle_callback_request(request)? {
                // Store the code
                let mut auth_code_guard = auth_code
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Failed to lock auth_code"))?;
                *auth_code_guard = Some(code.clone());

                return Ok(code);
            }
        }

        Err(anyhow::anyhow!("No valid callback received"))
    }

    /// Handle an incoming HTTP request to the callback server
    fn handle_callback_request(&self, request: Request) -> Result<Option<String>> {
        // Only handle GET requests to the callback path
        if request.method() != &Method::Get {
            self.send_error_response(request, "Only GET requests are supported")?;
            return Ok(None);
        }

        // Parse the URL to extract query parameters
        let url = format!("http://localhost{}", request.url());
        let parsed_url = Url::parse(&url)?;

        // Check if the URL contains an error parameter
        if let Some((_, error)) = parsed_url.query_pairs().find(|(k, _)| k == "error") {
            let error_msg = format!("Spotify authorization error: {}", error);
            self.send_error_response(request, &error_msg)?;
            return Err(anyhow::anyhow!(error_msg));
        }

        // Extract the authorization code
        if let Some((_, code)) = parsed_url.query_pairs().find(|(k, _)| k == "code") {
            // Send success response
            self.send_success_response(request)?;
            return Ok(Some(code.to_string()));
        }

        // No code found
        self.send_error_response(request, "No authorization code found in callback")?;
        Ok(None)
    }

    /// Send a success response to the user's browser
    fn send_success_response(&self, request: Request) -> Result<()> {
        let success_page = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Spotify Authentication Successful</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                .success { color: #2ecc71; font-size: 64px; margin-bottom: 20px; }
                h1 { color: #333; }
            </style>
        </head>
        <body>
            <div class="success">✓</div>
            <h1>Authentication Successful!</h1>
            <p>You have successfully authenticated with Spotify.</p>
            <p>You can now close this window and return to the application.</p>
        </body>
        </html>
        "#;

        let response = Response::from_string(success_page)
            .with_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap());

        request
            .respond(response)
            .map_err(|e| anyhow::anyhow!("Failed to send response: {}", e))?;

        Ok(())
    }

    /// Send an error response to the user's browser
    fn send_error_response(&self, request: Request, error: &str) -> Result<()> {
        let error_page = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <title>Spotify Authentication Error</title>
                <style>
                    body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }}
                    .error {{ color: #e74c3c; font-size: 64px; margin-bottom: 20px; }}
                    h1 {{ color: #333; }}
                    pre {{ background: #f8f8f8; padding: 10px; border-radius: 5px; text-align: left; margin: 20px auto; max-width: 800px; overflow: auto; }}
                </style>
            </head>
            <body>
                <div class="error">✗</div>
                <h1>Authentication Error</h1>
                <p>An error occurred during authentication with Spotify:</p>
                <pre>{}</pre>
                <p>Please close this window and try again.</p>
            </body>
            </html>
            "#,
            error
        );

        let response = Response::from_string(error_page)
            .with_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap())
            .with_status_code(400);

        request
            .respond(response)
            .map_err(|e| anyhow::anyhow!("Failed to send response: {}", e))?;

        Ok(())
    }

    /// Exchange the authorization code for access and refresh tokens
    fn exchange_code_for_tokens(
        &self,
        authorization_code: &str,
        code_verifier: Option<&str>,
    ) -> Result<SpotifyTokens> {
        println!("Exchanging authorization code for tokens...");

        // Prepare the token request parameters
        let mut params = HashMap::new();
        params.insert("client_id", self.config.client_id.clone());
        params.insert("client_secret", self.config.client_secret.clone());
        params.insert("grant_type", "authorization_code".to_string());
        params.insert("code", authorization_code.to_string());
        params.insert("redirect_uri", self.config.redirect_uri.clone());

        if self.use_pkce {
            if let Some(verifier) = code_verifier {
                params.insert("code_verifier", verifier.to_string());
            }
        }

        // Make the POST request to the token endpoint
        let response = self
            .http_client
            .post("https://accounts.spotify.com/api/token")
            .form(&params)
            .send()?;

        // Check for errors
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text()?;
            let error_msg = format!(
                "Error exchanging code for tokens: HTTP {}: {}",
                status, error_text
            );
            return Err(anyhow::anyhow!(error_msg));
        }

        // Parse the response into SpotifyTokens
        let tokens: SpotifyTokens = response.json()?;

        println!("Authentication successful! Received access token.");

        Ok(tokens)
    }
}
