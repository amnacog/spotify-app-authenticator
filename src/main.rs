mod config;
mod spotify_auth;

use anyhow::{Context, Result};
use clap::Parser;
use config::Config;
use spotify_auth::{SpotifyAuthenticator, SpotifyTokens};
use std::path::PathBuf;

/// Command line arguments for the application
#[derive(Parser, Debug)]
#[clap(author, version, about = "Spotify API Authentication Tool")]
struct Args {
    /// Path to the configuration JSON file
    #[clap(short, long, value_parser)]
    config_file: PathBuf,

    /// Optional output file to save the tokens as JSON
    #[clap(short, long, value_parser)]
    output_file: Option<PathBuf>,

    /// Use PKCE (Proof Key for Code Exchange) for enhanced security
    #[clap(long)]
    pkce: bool,
}

fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Load the configuration
    println!("Loading configuration from {:?}", args.config_file);
    let config = Config::from_file(&args.config_file).context("Failed to load configuration")?;

    println!("Loaded configuration with client ID: {}", config.client_id);
    println!("Requested scopes: {}", config.scopes_string());

    // Create the authenticator
    let authenticator = SpotifyAuthenticator::new(config, args.pkce);

    // Run the authentication flow
    let tokens = authenticator
        .authenticate()
        .context("Authentication failed")?;

    // Print the token info to console
    print_token_info(&tokens);

    // Save tokens to file if an output file was specified
    if let Some(output_path) = args.output_file {
        save_tokens_to_file(&tokens, &output_path)?;
    }

    Ok(())
}

/// Print information about the tokens to the console
fn print_token_info(tokens: &SpotifyTokens) {
    println!("\n=== Token Information ===");
    println!("Access Token: {}...", &tokens.access_token[0..10]);
    println!("Refresh Token: {}", tokens.refresh_token);
    println!("Token Type: {}", tokens.token_type);
    println!("Expires In: {} seconds", tokens.expires_in);
    println!("Scopes: {}", tokens.scope);
}

/// Save the tokens to a JSON file
fn save_tokens_to_file(tokens: &SpotifyTokens, path: &PathBuf) -> Result<()> {
    println!("Saving tokens to {:?}", path);
    let json = serde_json::to_string_pretty(tokens)?;
    std::fs::write(path, json)?;
    println!("Tokens saved successfully.");
    Ok(())
}
