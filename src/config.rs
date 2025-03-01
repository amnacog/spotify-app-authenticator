use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Represents the application configuration loaded from the JSON config file
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// The Spotify application client ID
    pub client_id: String,
    /// The Spotify application client secret
    pub client_secret: String,
    /// The OAuth redirect URI (must match the one configured in Spotify developer dashboard)
    pub redirect_uri: String,
    /// List of Spotify API scopes the application will request
    pub scopes: Vec<String>,
    /// The port on which the local HTTP server will listen
    pub port: u16,
}

impl Config {
    /// Load configuration from a file path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        // Read the file content as a string
        let file_content = fs::read_to_string(path)?;
        
        // Parse the JSON content into the Config struct
        let config: Config = serde_json::from_str(&file_content)?;
        
        // Validate the configuration
        config.validate()?;
        
        Ok(config)
    }
    
    /// Validate the configuration values
    fn validate(&self) -> Result<()> {
        // Check if client_id is present
        if self.client_id.is_empty() {
            return Err(anyhow::anyhow!("client_id cannot be empty"));
        }
        
        // Check if client_secret is present
        if self.client_secret.is_empty() {
            return Err(anyhow::anyhow!("client_secret cannot be empty"));
        }
        
        // Check if redirect_uri is valid
        if !self.redirect_uri.starts_with("http://") && !self.redirect_uri.starts_with("https://") {
            return Err(anyhow::anyhow!("redirect_uri must be an HTTP or HTTPS URL"));
        }
        
        // Check if port is not privileged (< 1024)
        if self.port < 1024 {
            return Err(anyhow::anyhow!("port must be >= 1024 (non-privileged)"));
        }
        
        Ok(())
    }
    
    /// Get the scopes as a space-separated string for use in the Spotify API
    pub fn scopes_string(&self) -> String {
        self.scopes.join(" ")
    }
}