use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::subtle::ConstantTimeEq;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use p256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};
use tokio::sync::{mpsc, Mutex};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

mod db;
use db::{QueuedMessage, User};

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<rusqlite::Connection>>,
    connections: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<String>>>>,
    challenges: Arc<Mutex<HashMap<String, PendingChallenge>>>,
}

#[derive(Clone)]
struct PendingChallenge {
    username: String,
    expected_response: Vec<u8>,
    created_at: Instant,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    public_key: Option<String>,
    token: Option<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    success: bool,
    message: String,
    user: Option<User>,
    token: Option<String>,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
}

#[derive(Serialize)]
struct LoginResponse {
    success: bool,
    message: String,
    user: Option<User>,
    requires_challenge: bool,
}

#[derive(Deserialize)]
struct ChallengeRequest {
    username: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    success: bool,
    message: String,
    challenge_id: Option<String>,
    server_ephemeral_pub: Option<String>,
    nonce: Option<String>,
}

#[derive(Deserialize)]
struct VerifyChallengeRequest {
    username: String,
    challenge_id: String,
    response: String,
}

#[derive(Serialize)]
struct VerifyChallengeResponse {
    success: bool,
    token: Option<String>,
    username: String,
    message: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    users_registered: usize,
    users_online: usize,
}

#[derive(Serialize)]
struct PublicKeyResponse {
    success: bool,
    username: String,
    public_key: Option<String>,
}

#[derive(Deserialize)]
struct UploadPrekeysRequest {
    username: String,
    signed_prekey: String,
    one_time_prekeys: Vec<String>,
    token: Option<String>,
}

#[derive(Deserialize)]
struct AppendPrekeysRequest {
    username: String,
    one_time_prekeys: Vec<String>,
    token: Option<String>,
}

#[derive(Serialize)]
struct UploadPrekeysResponse {
    success: bool,
    message: String,
}

#[derive(Serialize)]
struct PrekeysCountResponse {
    success: bool,
    username: String,
    count: usize,
    signed_prekey_present: bool,
}

#[derive(Serialize)]
struct PrekeyBundleResponse {
    success: bool,
    username: String,
    identity_key: Option<String>,
    signed_prekey: Option<String>,
    one_time_prekey: Option<String>, // consumed atomically if present
    opks_remaining: usize,
    message: String,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientMsg {
    #[serde(rename = "auth")]
    Auth {
        username: String,
        token: Option<String>,
    },
    #[serde(rename = "message")]
    Message { to: String, text: String },
    #[serde(rename = "ping")]
    Ping,
}

// ─── Cryptographic Challenge-Response Helpers ──────────────────────────────

fn compute_challenge_ecdh(
    client_spki_b64: &str,
) -> Result<(String, String, Vec<u8>), String> {
    let der_bytes = BASE64
        .decode(client_spki_b64.trim())
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    let client_pub = PublicKey::from_public_key_der(&der_bytes)
        .map_err(|e| format!("Invalid public key SPKI DER: {}", e))?;

    let server_secret = SecretKey::random(&mut rand::thread_rng());
    let server_pub = server_secret.public_key();
    let server_pub_der = server_pub
        .to_public_key_der()
        .map_err(|e| format!("Failed to encode server public key: {}", e))?;
    let server_pub_b64 = BASE64.encode(server_pub_der.as_bytes());

    let shared = p256::ecdh::diffie_hellman(
        server_secret.to_nonzero_scalar(),
        client_pub.as_affine(),
    );

    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let nonce_b64 = BASE64.encode(&nonce);

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(shared.raw_secret_bytes().as_slice())
        .map_err(|e| format!("HMAC init error: {}", e))?;
    mac.update(&nonce);
    let expected = mac.finalize().into_bytes().to_vec();

    Ok((server_pub_b64, nonce_b64, expected))
}

fn extract_bearer_token(
    headers: &HeaderMap,
    fallback_token: Option<&str>,
) -> Option<String> {
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(val) = auth_header.to_str() {
            if let Some(token) = val.strip_prefix("Bearer ") {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    fallback_token
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

async fn verify_user_session(
    state: &AppState,
    username: &str,
    headers: &HeaderMap,
    fallback_token: Option<&str>,
) -> bool {
    let token = match extract_bearer_token(headers, fallback_token) {
        Some(t) => t,
        None => return false,
    };

    let db = state.db.lock().await;
    db::verify_session(&db, &token, username).unwrap_or(false)
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentinel_backend=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_path = db::get_db_path();
    let conn = match db::init_db(&db_path) {
        Ok(c) => {
            tracing::info!("SQLite persistence initialized at: {}", db_path);
            c
        }
        Err(e) => {
            tracing::error!("Fatal: Failed to initialize SQLite database: {}", e);
            std::process::exit(1);
        }
    };

    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        connections: Arc::new(Mutex::new(HashMap::new())),
        challenges: Arc::new(Mutex::new(HashMap::new())),
    };

    let cors = if let Ok(allowed) = std::env::var("ALLOWED_ORIGINS") {
        let origins: Vec<HeaderValue> = allowed
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<HeaderValue>().ok())
            .collect();

        if !origins.is_empty() {
            tracing::info!(
                "CORS configured with explicit allowed origins (production lock): {:?}",
                origins
            );
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods(Any)
                .allow_headers(Any)
        } else {
            tracing::warn!("ALLOWED_ORIGINS was empty; defaulting to permissive CORS for development");
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        }
    } else {
        tracing::info!("ALLOWED_ORIGINS not set; defaulting to permissive CORS for local development");
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    };

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/api/auth/challenge", post(create_challenge))
        .route("/api/auth/verify", post(verify_challenge))
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/public-key/{username}", get(get_public_key))
        .route("/api/prekeys", post(upload_prekeys))
        .route("/api/prekeys/append", post(append_prekeys))
        .route("/api/prekeys-count/{username}", get(get_prekeys_count))
        .route("/api/prekey-bundle/{username}", get(get_prekey_bundle))
        .route("/ws", get(ws_handler))
        .layer(cors)
        .with_state(state);

    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 8080)));
    tracing::info!("Sentinel backend listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    "Sentinel Backend v0.3.0 — Secure Messaging API (SQLite Persistence + X3DH + ECDH Auth)"
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let registered = {
        let db = state.db.lock().await;
        db::count_users(&db).unwrap_or(0)
    };
    let online = state.connections.lock().await.len();
    Json(HealthResponse {
        status: "ok".into(),
        version: "0.3.0".into(),
        users_registered: registered,
        users_online: online,
    })
}

async fn create_challenge(
    State(state): State<AppState>,
    Json(payload): Json<ChallengeRequest>,
) -> impl IntoResponse {
    let username = payload.username.trim().to_lowercase();
    let user = {
        let db = state.db.lock().await;
        match db::get_user(&db, &username) {
            Ok(Some(u)) => u,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ChallengeResponse {
                        success: false,
                        message: format!("User '{}' not found", username),
                        challenge_id: None,
                        server_ephemeral_pub: None,
                        nonce: None,
                    }),
                );
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ChallengeResponse {
                        success: false,
                        message: format!("Database error: {}", e),
                        challenge_id: None,
                        server_ephemeral_pub: None,
                        nonce: None,
                    }),
                );
            }
        }
    };

    let pubkey_b64 = match user.public_key {
        Some(ref pk) if !pk.is_empty() => pk.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ChallengeResponse {
                    success: false,
                    message: format!("User '{}' has no registered public key", username),
                    challenge_id: None,
                    server_ephemeral_pub: None,
                    nonce: None,
                }),
            );
        }
    };

    match compute_challenge_ecdh(&pubkey_b64) {
        Ok((server_pub_b64, nonce_b64, expected)) => {
            let challenge_id = Uuid::new_v4().to_string();
            let mut challenges = state.challenges.lock().await;
            let now = Instant::now();
            challenges.retain(|_, c| now.duration_since(c.created_at).as_secs() < 60);

            challenges.insert(
                challenge_id.clone(),
                PendingChallenge {
                    username: username.clone(),
                    expected_response: expected,
                    created_at: now,
                },
            );

            (
                StatusCode::OK,
                Json(ChallengeResponse {
                    success: true,
                    message: "Cryptographic challenge created".into(),
                    challenge_id: Some(challenge_id),
                    server_ephemeral_pub: Some(server_pub_b64),
                    nonce: Some(nonce_b64),
                }),
            )
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ChallengeResponse {
                success: false,
                message: format!("Failed to generate challenge: {}", err),
                challenge_id: None,
                server_ephemeral_pub: None,
                nonce: None,
            }),
        ),
    }
}

async fn verify_challenge(
    State(state): State<AppState>,
    Json(payload): Json<VerifyChallengeRequest>,
) -> impl IntoResponse {
    let username = payload.username.trim().to_lowercase();
    let challenge_id = payload.challenge_id.trim();

    let mut challenges = state.challenges.lock().await;
    let challenge = match challenges.remove(challenge_id) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(VerifyChallengeResponse {
                    success: false,
                    token: None,
                    username,
                    message: "Challenge expired or invalid".into(),
                }),
            );
        }
    };
    drop(challenges);

    if !challenge.username.eq_ignore_ascii_case(&username) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(VerifyChallengeResponse {
                success: false,
                token: None,
                username,
                message: "Challenge username mismatch".into(),
            }),
        );
    }

    if Instant::now().duration_since(challenge.created_at).as_secs() > 60 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(VerifyChallengeResponse {
                success: false,
                token: None,
                username,
                message: "Challenge has expired (60s limit)".into(),
            }),
        );
    }

    let client_bytes = match BASE64.decode(payload.response.trim()) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyChallengeResponse {
                    success: false,
                    token: None,
                    username,
                    message: "Invalid base64 in challenge response".into(),
                }),
            );
        }
    };

    if client_bytes.len() != challenge.expected_response.len()
        || !bool::from(client_bytes.as_slice().ct_eq(challenge.expected_response.as_slice()))
    {
        tracing::warn!("Cryptographic challenge failed for user {}", username);
        return (
            StatusCode::UNAUTHORIZED,
            Json(VerifyChallengeResponse {
                success: false,
                token: None,
                username,
                message: "Cryptographic signature verification failed".into(),
            }),
        );
    }

    let token = Uuid::new_v4().to_string();
    {
        let db = state.db.lock().await;
        if let Err(e) = db::save_session(&db, &token, &username) {
            tracing::error!("Failed to save session to DB: {}", e);
        }
    }

    tracing::info!("User '{}' authenticated via challenge-response. Token issued.", username);

    (
        StatusCode::OK,
        Json(VerifyChallengeResponse {
            success: true,
            token: Some(token),
            username,
            message: "Authentication successful".into(),
        }),
    )
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let username = payload.username.trim().to_lowercase();

    if username.is_empty() || username.len() < 3 {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterResponse {
                success: false,
                message: "Username must be at least 3 characters".into(),
                user: None,
                token: None,
            }),
        );
    }

    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterResponse {
                success: false,
                message: "Username can only contain letters, numbers, _ and -".into(),
                user: None,
                token: None,
            }),
        );
    }

    let existing_user = {
        let db = state.db.lock().await;
        db::get_user(&db, &username).ok().flatten()
    };
    let is_update = existing_user.is_some();

    // If updating existing user keys, cryptographic authentication is strictly required
    if is_update {
        let authorized = verify_user_session(&state, &username, &headers, payload.token.as_deref()).await;
        if !authorized {
            return (
                StatusCode::UNAUTHORIZED,
                Json(RegisterResponse {
                    success: false,
                    message: "Identity re-registration or key rotation requires cryptographic authentication.".into(),
                    user: None,
                    token: None,
                }),
            );
        }
    }

    let user = User {
        id: existing_user.as_ref().map(|u| u.id.clone()).unwrap_or_else(|| Uuid::new_v4().to_string()),
        username: username.clone(),
        created_at: existing_user.as_ref().map(|u| u.created_at.clone()).unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        public_key: payload.public_key,
        signed_prekey: existing_user.as_ref().and_then(|u| u.signed_prekey.clone()),
        one_time_prekeys: vec![],
    };

    let token = Uuid::new_v4().to_string();
    {
        let db = state.db.lock().await;
        if let Err(e) = db::save_user(&db, &user) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RegisterResponse {
                    success: false,
                    message: format!("Failed to save user: {}", e),
                    user: None,
                    token: None,
                }),
            );
        }
        let _ = db::save_session(&db, &token, &username);
    }

    if is_update {
        tracing::info!("User identity re-registered / key rotated: {}", user.username);
    } else {
        tracing::info!("User registered: {}", user.username);
    }

    (
        StatusCode::CREATED,
        Json(RegisterResponse {
            success: true,
            message: if is_update {
                "Identity re-registered and keys rotated successfully".into()
            } else {
                "Identity created successfully".into()
            },
            user: Some(user),
            token: Some(token),
        }),
    )
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let username = payload.username.trim().to_lowercase();
    let user_opt = {
        let db = state.db.lock().await;
        db::get_user(&db, &username).ok().flatten()
    };

    match user_opt {
        Some(user) => {
            tracing::info!("User login query: {}", user.username);
            let requires_challenge = user.public_key.is_some();
            (
                StatusCode::OK,
                Json(LoginResponse {
                    success: true,
                    message: if requires_challenge {
                        "Identity found. Cryptographic challenge required.".into()
                    } else {
                        "Login successful".into()
                    },
                    user: Some(user),
                    requires_challenge,
                }),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(LoginResponse {
                success: false,
                message: format!(
                    "No identity found for '{}'. Use /register first.",
                    username
                ),
                user: None,
                requires_challenge: false,
            }),
        ),
    }
}

async fn get_public_key(
    State(state): State<AppState>,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> impl IntoResponse {
    let username = username.trim().to_lowercase();
    let user_opt = {
        let db = state.db.lock().await;
        db::get_user(&db, &username).ok().flatten()
    };

    match user_opt {
        Some(user) => (
            StatusCode::OK,
            Json(PublicKeyResponse {
                success: true,
                username: user.username,
                public_key: user.public_key,
            }),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(PublicKeyResponse {
                success: false,
                username,
                public_key: None,
            }),
        ),
    }
}

async fn upload_prekeys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UploadPrekeysRequest>,
) -> impl IntoResponse {
    let username = payload.username.trim().to_lowercase();

    let authorized = verify_user_session(&state, &username, &headers, payload.token.as_deref()).await;
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(UploadPrekeysResponse {
                success: false,
                message: "Unauthorized: Prekey upload requires cryptographic session token".into(),
            }),
        );
    }

    let mut db = state.db.lock().await;
    match db::get_user(&db, &username) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(UploadPrekeysResponse {
                    success: false,
                    message: format!("User '{}' not found", username),
                }),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UploadPrekeysResponse {
                    success: false,
                    message: format!("Database error: {}", e),
                }),
            );
        }
    }

    match db::replace_prekeys(&mut *db, &username, &payload.signed_prekey, &payload.one_time_prekeys) {
        Ok(count) => {
            tracing::info!("Prekeys uploaded for {} ({} one-time)", username, count);
            (
                StatusCode::OK,
                Json(UploadPrekeysResponse {
                    success: true,
                    message: "Prekeys uploaded".into(),
                }),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(UploadPrekeysResponse {
                success: false,
                message: format!("Failed to replace prekeys: {}", e),
            }),
        ),
    }
}

async fn append_prekeys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AppendPrekeysRequest>,
) -> impl IntoResponse {
    let username = payload.username.trim().to_lowercase();

    let authorized = verify_user_session(&state, &username, &headers, payload.token.as_deref()).await;
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(UploadPrekeysResponse {
                success: false,
                message: "Unauthorized: Prekey replenishment requires cryptographic session token".into(),
            }),
        );
    }

    let db = state.db.lock().await;
    match db::get_user(&db, &username) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(UploadPrekeysResponse {
                    success: false,
                    message: format!("User '{}' not found", username),
                }),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UploadPrekeysResponse {
                    success: false,
                    message: format!("Database error: {}", e),
                }),
            );
        }
    }

    let added = payload.one_time_prekeys.len();
    match db::append_one_time_prekeys(&db, &username, &payload.one_time_prekeys) {
        Ok(_) => {
            let total = db::count_one_time_prekeys(&db, &username).unwrap_or(0);
            tracing::info!("Appended {} prekeys for {} (total: {})", added, username, total);
            (
                StatusCode::OK,
                Json(UploadPrekeysResponse {
                    success: true,
                    message: format!("Appended {} prekeys (pool size: {})", added, total),
                }),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(UploadPrekeysResponse {
                success: false,
                message: format!("Failed to append prekeys: {}", e),
            }),
        ),
    }
}

async fn get_prekeys_count(
    State(state): State<AppState>,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> impl IntoResponse {
    let username = username.trim().to_lowercase();
    let db = state.db.lock().await;

    match db::get_user(&db, &username) {
        Ok(Some(user)) => {
            let count = db::count_one_time_prekeys(&db, &username).unwrap_or(0);
            (
                StatusCode::OK,
                Json(PrekeysCountResponse {
                    success: true,
                    username: user.username,
                    count,
                    signed_prekey_present: user.signed_prekey.is_some(),
                }),
            )
        }
        _ => (
            StatusCode::NOT_FOUND,
            Json(PrekeysCountResponse {
                success: false,
                username,
                count: 0,
                signed_prekey_present: false,
            }),
        ),
    }
}

async fn get_prekey_bundle(
    State(state): State<AppState>,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> impl IntoResponse {
    let username = username.trim().to_lowercase();
    let db = state.db.lock().await;

    let user = match db::get_user(&db, &username) {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(PrekeyBundleResponse {
                    success: false,
                    username,
                    identity_key: None,
                    signed_prekey: None,
                    one_time_prekey: None,
                    opks_remaining: 0,
                    message: "User not found".into(),
                }),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PrekeyBundleResponse {
                    success: false,
                    username,
                    identity_key: None,
                    signed_prekey: None,
                    one_time_prekey: None,
                    opks_remaining: 0,
                    message: format!("Database error: {}", e),
                }),
            );
        }
    };

    if user.public_key.is_none() || user.signed_prekey.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(PrekeyBundleResponse {
                success: false,
                username: user.username,
                identity_key: None,
                signed_prekey: None,
                one_time_prekey: None,
                opks_remaining: 0,
                message: "User has no prekeys uploaded yet".into(),
            }),
        );
    }

    let one_time_prekey = db::consume_one_time_prekey(&db, &username).unwrap_or(None);
    let opks_remaining = db::count_one_time_prekeys(&db, &username).unwrap_or(0);

    (
        StatusCode::OK,
        Json(PrekeyBundleResponse {
            success: true,
            username: user.username,
            identity_key: user.public_key,
            signed_prekey: user.signed_prekey,
            one_time_prekey,
            opks_remaining,
            message: "Prekey bundle ready".into(),
        }),
    )
}

// ─── WebSocket ──────────────────────────────────────────────────────────────

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    let mut authed_user: Option<String> = None;
    let recv_state = state.clone();

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    let text = text.to_string();
                    match serde_json::from_str::<ClientMsg>(&text) {
                        Ok(ClientMsg::Auth { username, token }) => {
                            let username = username.trim().to_lowercase();
                            let exists = {
                                let db = recv_state.db.lock().await;
                                db::get_user(&db, &username).ok().flatten().is_some()
                            };

                            if !exists {
                                let err = serde_json::json!({
                                    "type": "auth_error",
                                    "message": format!("Unknown user '{}'. Register first.", username)
                                });
                                let _ = tx.send(err.to_string());
                                continue;
                            }

                            // Verify cryptographic session token
                            let token_valid = if let Some(ref t) = token {
                                let db = recv_state.db.lock().await;
                                db::verify_session(&db, t, &username).unwrap_or(false)
                            } else {
                                false
                            };

                            if !token_valid {
                                let err = serde_json::json!({
                                    "type": "auth_error",
                                    "message": "Cryptographic authentication failed. Valid session token required."
                                });
                                let _ = tx.send(err.to_string());
                                continue;
                            }

                            {
                                let mut conns = recv_state.connections.lock().await;
                                conns.insert(username.clone(), tx.clone());
                            }

                            authed_user = Some(username.clone());
                            tracing::info!("WS auth: {}", username);

                            let ok = serde_json::json!({
                                "type": "auth_ok",
                                "username": username,
                                "message": "Authenticated on WebSocket"
                            });
                            let _ = tx.send(ok.to_string());

                            // Deliver queued offline messages
                            let pending = {
                                let db = recv_state.db.lock().await;
                                db::pop_queued_messages(&db, &username).unwrap_or_default()
                            };

                            if !pending.is_empty() {
                                let count = pending.len();
                                tracing::info!(
                                    "Delivering {} queued messages to {}",
                                    count,
                                    username
                                );
                                let info = serde_json::json!({
                                    "type": "system",
                                    "message": format!("Delivering {} offline message(s)...", count)
                                });
                                let _ = tx.send(info.to_string());

                                for qm in pending {
                                    let payload = serde_json::json!({
                                        "type": "message",
                                        "from": qm.from,
                                        "to": qm.to,
                                        "text": qm.text,
                                        "ts": qm.ts
                                    });
                                    let _ = tx.send(payload.to_string());
                                }
                            }

                            let online = recv_state.connections.lock().await.len();
                            let info = serde_json::json!({
                                "type": "system",
                                "message": format!("You are online. {} user(s) connected.", online)
                            });
                            let _ = tx.send(info.to_string());
                        }

                        Ok(ClientMsg::Message { to, text }) => {
                            let from = match &authed_user {
                                Some(u) => u.clone(),
                                None => {
                                    let err = serde_json::json!({
                                        "type": "system",
                                        "message": "Not authenticated. Send auth first."
                                    });
                                    let _ = tx.send(err.to_string());
                                    continue;
                                }
                            };

                            let to = to.trim().to_lowercase();
                            let text = text.trim();
                            if text.is_empty() {
                                continue;
                            }
                            if to == from {
                                let err = serde_json::json!({
                                    "type": "system",
                                    "message": "Cannot message yourself."
                                });
                                let _ = tx.send(err.to_string());
                                continue;
                            }

                            let recipient_exists = {
                                let db = recv_state.db.lock().await;
                                db::get_user(&db, &to).ok().flatten().is_some()
                            };

                            if !recipient_exists {
                                let err = serde_json::json!({
                                    "type": "system",
                                    "message": format!("User '{}' does not exist.", to)
                                });
                                let _ = tx.send(err.to_string());
                                continue;
                            }

                            let payload = serde_json::json!({
                                "type": "message",
                                "from": from,
                                "to": to,
                                "text": text,
                                "ts": chrono::Utc::now().to_rfc3339()
                            });

                            let delivered = {
                                let conns = recv_state.connections.lock().await;
                                if let Some(target_tx) = conns.get(&to) {
                                    target_tx.send(payload.to_string()).is_ok()
                                } else {
                                    false
                                }
                            };

                            if delivered {
                                let ack = serde_json::json!({
                                    "type": "delivered",
                                    "to": to
                                });
                                let _ = tx.send(ack.to_string());
                                tracing::info!("Message {} → {}: delivered live", from, to);
                            } else {
                                let qm = QueuedMessage {
                                    from: from.clone(),
                                    to: to.clone(),
                                    text: text.to_string(),
                                    ts: chrono::Utc::now().to_rfc3339(),
                                };

                                {
                                    let db = recv_state.db.lock().await;
                                    if let Err(e) = db::enqueue_message(&db, &qm) {
                                        tracing::error!("Failed to enqueue offline message: {}", e);
                                    }
                                }

                                let info = serde_json::json!({
                                    "type": "system",
                                    "message": format!("User '{}' is offline. Message queued for delivery.", to)
                                });
                                let _ = tx.send(info.to_string());
                                tracing::info!("Message {} → {}: queued offline", from, to);
                            }
                        }

                        Ok(ClientMsg::Ping) => {
                            let pong = serde_json::json!({
                                "type": "pong",
                                "ts": chrono::Utc::now().timestamp()
                            });
                            let _ = tx.send(pong.to_string());
                        }

                        Err(_) => {}
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }

        if let Some(user) = authed_user {
            let mut conns = recv_state.connections.lock().await;
            conns.remove(&user);
            tracing::info!("WS disconnect: {}", user);
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }
}