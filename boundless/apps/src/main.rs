// Host: post a single Boundless request that timestamps one document, then
// settle the returned proof on the DocumentTimeOracle contract.
//
// Repeating this — one single request per document — is how the app synthesises
// an on-chain time oracle. Everything else (threads, summonses, the document
// hash itself) is produced by the thr34ds app; this binary only handles the
// Boundless round-trip for a single document hash + claimed window.
//
// API mirrors the Boundless foundry template (boundless-xyz/boundless-foundry-
// template). Pricing uses the client's default offer layer, which relies on
// Boundless's built-in USD price oracle to convert the offer to token at
// request time — no hand-set token amounts.

use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, FixedBytes, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolValue,
};
use anyhow::{Context, Result};
use boundless_market::{Client, Deployment, StorageProviderConfig};
use clap::Parser;
use guests::TIME_ORACLE_ELF;
use url::Url;

// Minimal ABI for the consumer contract's settle() entrypoint.
sol! {
    #[sol(rpc)]
    interface IDocumentTimeOracle {
        function settle(bytes calldata seal, bytes32 documentHash, uint256 midpointMs, uint256 radiusMs) external;
    }
}

#[derive(Parser)]
#[command(about = "Timestamp one document on-chain via a single Boundless request")]
struct Args {
    /// Ethereum RPC endpoint.
    #[arg(long, env = "RPC_URL")]
    rpc_url: Url,

    /// Requestor private key (funded on the target chain).
    #[arg(long, env = "PRIVATE_KEY")]
    private_key: PrivateKeySigner,

    /// Boundless deployment (chain / market addresses). Defaults to the env-
    /// configured deployment.
    #[command(flatten)]
    deployment: Option<Deployment>,

    /// Storage provider config for uploading the guest program (e.g. Pinata).
    #[command(flatten)]
    storage_config: StorageProviderConfig,

    /// Public URL of the uploaded guest program. If omitted, the embedded ELF
    /// is uploaded via the configured storage provider.
    #[arg(long)]
    program_url: Option<Url>,

    /// Deployed DocumentTimeOracle contract.
    #[arg(long, env = "DOCUMENT_TIME_ORACLE_ADDRESS")]
    oracle_address: Address,

    /// The document hash (Roughtime nonce), 0x-prefixed 32 bytes — produced by
    /// the app (`summons.content_hash()` / `oracle.js` nonce).
    #[arg(long)]
    document_hash: FixedBytes<32>,

    /// Claimed window midpoint (unix milliseconds).
    #[arg(long)]
    midpoint_ms: u64,

    /// Claimed window radius (milliseconds).
    #[arg(long, default_value_t = 10_000)]
    radius_ms: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    let midpoint = U256::from(args.midpoint_ms);
    let radius = U256::from(args.radius_ms);

    // The guest input: ABI-encoded (bytes32, uint256, uint256).
    let input = (args.document_hash, midpoint, radius).abi_encode();

    // 1. Build the Boundless client.
    let client = Client::builder()
        .with_rpc_url(args.rpc_url.clone())
        .with_deployment(args.deployment)
        .with_storage_provider_config(&args.storage_config)?
        .with_private_key(args.private_key.clone())
        .build()
        .await
        .context("failed to build boundless client")?;

    // 2. Compose the request. Either reference an already-uploaded program URL
    //    or embed the ELF (the client uploads it via the storage provider).
    //    The default offer layer prices the request in USD via Boundless's
    //    built-in price oracle.
    let request = match args.program_url {
        Some(url) => client.new_request().with_program_url(url)?.with_stdin(input),
        None => client.new_request().with_program(TIME_ORACLE_ELF).with_stdin(input),
    };

    // 3. Submit a single request and wait for a prover to fulfill it.
    let (request_id, expires_at) = client.submit(request).await?;
    tracing::info!("submitted Boundless request 0x{request_id:x}");

    let fulfillment = client
        .wait_for_request_fulfillment(request_id, Duration::from_secs(5), expires_at)
        .await?;
    tracing::info!("request fulfilled; settling on-chain");

    // 4. Settle on-chain: the contract verifies the seal and stamps
    //    block.timestamp, corroborating the claimed window against chain time.
    let wallet = EthereumWallet::from(args.private_key);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(args.rpc_url);
    let oracle = IDocumentTimeOracle::new(args.oracle_address, provider);

    let pending = oracle
        .settle(fulfillment.seal, args.document_hash, midpoint, radius)
        .send()
        .await?;
    let receipt = pending.get_receipt().await?;
    tracing::info!(
        "document {:#x} timestamped on-chain in tx {:#x}",
        args.document_hash,
        receipt.transaction_hash
    );

    Ok(())
}
