use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub type ApiResult<T> = Result<T, ApiError>;

tokio::task_local! {
    /// Id of the request being handled (`x-request-id`), set by `main::request_id`.
    pub static REQUEST_ID: String;
}

/// The current request's id, inside a request.
pub fn request_id() -> Option<String> {
    REQUEST_ID.try_with(Clone::clone).ok()
}

/// Machine-readable reasons (`error` in the JSON body) for cases clients act on.
/// Statuses without one use the generic code of the status (`bad_request`,
/// `forbidden`, `conflict`…). Messages stay as they were: older clients compare them.
pub mod code {
    /// 400: a pending step (sign-in, registration, setup, email link) is gone; start again.
    pub const EXPIRED: &str = "expired";
    /// 400: a wrong two-step, setup or email code.
    pub const INVALID_CODE: &str = "invalid_code";
    /// 401: the session reached its absolute lifetime; sign in again.
    pub const SESSION_EXPIRED: &str = "session_expired";
    /// 403: the account must confirm its email before signing in.
    pub const EMAIL_NOT_VERIFIED: &str = "email_not_verified";
    /// 403: this action needs a fresh master-password confirmation (`x-reauth-token`).
    pub const REAUTH_REQUIRED: &str = "reauth_required";
    /// 403: the account was disabled by the admin.
    pub const ACCOUNT_DISABLED: &str = "account_disabled";
    /// 403: the vault owner's item or storage limit (admin page) would be passed.
    pub const QUOTA_EXCEEDED: &str = "quota_exceeded";
    /// 403: self-registration is closed (or limited to other email domains).
    pub const SIGNUPS_CLOSED: &str = "signups_closed";
    /// 409: the request used a vault key that has since been replaced; nothing was written.
    pub const VAULT_KEY_CHANGED: &str = "vault_key_changed";
    /// 409: an item write carried a revision that is no longer the stored one.
    pub const REVISION_CONFLICT: &str = "revision_conflict";
    /// 409: an item with this id already exists with different contents.
    pub const ITEM_EXISTS: &str = "item_exists";
    /// 409: a vault with this id already exists.
    pub const VAULT_EXISTS: &str = "vault_exists";
    /// 409: an account with this email already exists.
    pub const ACCOUNT_EXISTS: &str = "account_exists";
    /// 409: the user's last own vault can't be deleted.
    pub const LAST_VAULT: &str = "last_vault";
    /// 409: the two-step method is already on.
    pub const ALREADY_ENABLED: &str = "already_enabled";
    /// 403: the server requires two-step login and the account has no method yet
    /// (only setting one up, `GET /account` and signing out still work), or the
    /// request would remove the account's last method.
    pub const TWO_STEP_REQUIRED: &str = "two_step_required";
    /// 400: the server requires a Secret Key; the new account keys don't use one.
    pub const SECRET_KEY_REQUIRED: &str = "secret_key_required";
    /// 400: the new account keys' key derivation is below the server's minimum.
    pub const KDF_TOO_WEAK: &str = "kdf_too_weak";
    /// 401: a Send's password (its verifier) is wrong.
    pub const WRONG_PASSWORD: &str = "wrong_password";
    /// 403: the admin turned Send off.
    pub const SENDS_DISABLED: &str = "sends_disabled";
    /// 413: a request or upload is larger than this server allows.
    pub const TOO_LARGE: &str = "too_large";
    /// 403: the admin turned attachments off, or the server has no folder for them.
    pub const ATTACHMENTS_DISABLED: &str = "attachments_disabled";
    /// 409: an attachment with this id already exists for another item or size.
    pub const ATTACHMENT_EXISTS: &str = "attachment_exists";
    /// 409: the attachment's file was already uploaded (an earlier try landed).
    pub const ALREADY_UPLOADED: &str = "already_uploaded";
    /// 409: another upload of this attachment is running.
    pub const UPLOAD_IN_PROGRESS: &str = "upload_in_progress";
    /// 403: the admin turned emergency access off.
    pub const EMERGENCY_ACCESS_DISABLED: &str = "emergency_access_disabled";
    /// 403: the admin turned signing in with another device's approval off.
    pub const LOGIN_WITH_DEVICE_DISABLED: &str = "login_with_device_disabled";
    /// 507: the server's disk is down to the admin's free-space reserve
    /// (`min_free_disk_mb`); nothing new is stored until space is freed. Reading,
    /// syncing and deleting still work.
    pub const INSUFFICIENT_STORAGE: &str = "insufficient_storage";
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("{0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    /// 429; the value is the `Retry-After` in seconds.
    #[error("too many requests, try again later")]
    TooManyRequests(u64),
    /// Any status with its own `error` code (see [`code`]).
    #[error("{message}")]
    Coded {
        status: StatusCode,
        code: &'static str,
        message: String,
    },
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl ApiError {
    pub fn bad(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    pub fn coded(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self::Coded {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn expired(msg: &str) -> Self {
        Self::coded(StatusCode::BAD_REQUEST, code::EXPIRED, msg)
    }

    pub fn invalid_code(msg: &str) -> Self {
        Self::coded(StatusCode::BAD_REQUEST, code::INVALID_CODE, msg)
    }

    pub fn reauth_required() -> Self {
        Self::coded(
            StatusCode::FORBIDDEN,
            code::REAUTH_REQUIRED,
            "reauth_required",
        )
    }

    pub fn vault_key_changed() -> Self {
        Self::coded(
            StatusCode::CONFLICT,
            code::VAULT_KEY_CHANGED,
            "the vault's key was replaced; sync and try again",
        )
    }

    pub fn quota_exceeded() -> Self {
        Self::coded(
            StatusCode::FORBIDDEN,
            code::QUOTA_EXCEEDED,
            "storage limit reached",
        )
    }

    /// `quota_exceeded` for the admin's attachment storage limit per user.
    pub fn attachment_quota_exceeded() -> Self {
        Self::coded(
            StatusCode::FORBIDDEN,
            code::QUOTA_EXCEEDED,
            "attachment storage limit reached",
        )
    }

    pub fn insufficient_storage() -> Self {
        Self::coded(
            StatusCode::INSUFFICIENT_STORAGE,
            code::INSUFFICIENT_STORAGE,
            "the server is almost out of disk space, so nothing new can be saved right now; deleting still works. Ask the server's admin to free up space",
        )
    }

    pub fn revision_conflict(msg: &str) -> Self {
        Self::coded(StatusCode::CONFLICT, code::REVISION_CONFLICT, msg)
    }

    /// 409 with `code` when `e` is a unique-constraint violation; any other
    /// database error (busy, disconnected…) stays an internal error.
    pub fn conflict_on_unique(e: sqlx::Error, code: &'static str, msg: &str) -> Self {
        if e.as_database_error()
            .is_some_and(|d| d.is_unique_violation())
        {
            Self::coded(StatusCode::CONFLICT, code, msg)
        } else {
            e.into()
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized | Self::InvalidCredentials => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Coded { status, .. } => *status,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::InvalidCredentials => "invalid_credentials",
            Self::Forbidden(_) => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict(_) => "conflict",
            Self::TooManyRequests(_) => "rate_limited",
            Self::Coded { code, .. } => code,
            Self::Internal(_) => "internal",
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(e.into())
    }
}

impl From<passauth_core::Error> for ApiError {
    fn from(e: passauth_core::Error) -> Self {
        Self::BadRequest(e.to_string())
    }
}

/// The JSON error body: `{"error", "message", "request_id"}`.
pub fn body(code: &str, message: &str) -> serde_json::Value {
    let mut body = json!({ "error": code, "message": message });
    if let Some(id) = request_id() {
        body["request_id"] = id.into();
    }
    body
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(e) = &self {
            tracing::error!(error = ?e, request_id = request_id().unwrap_or_default(), "internal error");
        }
        let mut resp = (self.status(), Json(body(self.code(), &self.to_string()))).into_response();
        if let Self::TooManyRequests(secs) = self {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs.max(1)));
        }
        resp
    }
}
