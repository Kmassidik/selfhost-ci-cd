//! SSR server: login, dashboard, security headers.
//!
//! No client-side JavaScript, no JSON API. Every page is rendered server-side from a template,
//! and every route except `/healthz`, `/login` and `/assets/*` requires a session.

use crate::auth::{self, LockState, Sessions, Throttle};
use crate::config::{Config, Secrets};
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Form, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use std::sync::Arc;
use cookie::time::Duration as CookieDuration;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const CSS: &str = include_str!("../assets/app.css");
const COOKIE_SESSION: &str = "cicd_sid";
const COOKIE_CSRF: &str = "cicd_csrf";

pub struct AppState {
    pub cfg: Config,
    pub sessions: Sessions,
    pub throttle: Throttle,
    pub password_hash: String,
    pub secure_cookies: bool,
}

// ------------------------------------------------------------------ templates

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
struct LoginPage {
    instance: String,
    csrf: String,
    username: String,
    error: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    instance: String,
    user: String,
    csrf: String,
    version: String,
    baseline: String,
    probe: String,
    ingress: String,
    backends: String,
    targets: String,
    sessions: usize,
}

// ------------------------------------------------------------------ handlers

async fn healthz(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    // Deliberately terse: a version string and nothing else.
    let _ = &app.cfg;
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain")], format!("ok {VERSION}\n"))
}

async fn stylesheet() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        CSS,
    )
}

async fn login_page(State(app): State<Arc<AppState>>, jar: CookieJar) -> Response {
    if let Some(sid) = jar.get(COOKIE_SESSION).map(|c| c.value().to_string()) {
        if app.sessions.get(&sid).is_some() {
            return Redirect::to("/").into_response();
        }
    }
    let csrf = crate::crypto::random_token(32);
    let cookie = Cookie::build((COOKIE_CSRF, csrf.clone()))
        .path("/login")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(app.secure_cookies)
        .max_age(CookieDuration::seconds(auth::CSRF_TTL.as_secs() as i64))
        .build();
    let page = LoginPage {
        instance: app.cfg.instance.name.clone(),
        csrf,
        username: String::new(),
        error: String::new(),
    };
    let mut res = page.into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie.to_string()) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    res
}

#[derive(Deserialize)]
struct LoginForm {
    csrf: String,
    username: String,
    password: String,
}

async fn login_submit(
    State(app): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    let fail = |app: &AppState, jar: CookieJar, error: String, username: String| -> Response {
        let csrf = jar
            .get(COOKIE_CSRF)
            .map(|c| c.value().to_string())
            .unwrap_or_else(|| crate::crypto::random_token(32));
        let page = LoginPage {
            instance: app.cfg.instance.name.clone(),
            csrf,
            username,
            error,
        };
        (StatusCode::UNAUTHORIZED, page).into_response()
    };

    // CSRF: the form token must match the cookie that issued it.
    let cookie_csrf = jar.get(COOKIE_CSRF).map(|c| c.value().to_string());
    match cookie_csrf {
        Some(c) if constant_eq(&c, &form.csrf) => {}
        _ => {
            return fail(&app, jar, "Session expired. Try again.".into(), form.username);
        }
    }

    match app.throttle.check(&form.username) {
        LockState::Locked(left) => {
            let mins = left.as_secs() / 60 + 1;
            return fail(
                &app,
                jar,
                format!("Too many attempts. Try again in {mins} min."),
                form.username,
            );
        }
        LockState::Open => {}
    }

    let user_ok = constant_eq(&form.username, &app.cfg.instance.admin_user);
    let pass_ok = auth::verify_password(&form.password, &app.password_hash);

    if !(user_ok && pass_ok) {
        let left = app.throttle.fail(&form.username);
        let msg = if left == 0 {
            "Too many attempts. Locked for 5 min.".to_string()
        } else {
            "Invalid credentials.".to_string()
        };
        return fail(&app, jar, msg, form.username);
    }

    app.throttle.clear(&form.username);
    let (sid, _csrf) = app.sessions.create(&form.username);

    let sid_cookie = Cookie::build((COOKIE_SESSION, sid))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(app.secure_cookies)
        .max_age(CookieDuration::hours(12))
        .build();
    let clear_csrf = Cookie::build((COOKIE_CSRF, ""))
        .path("/login")
        .max_age(CookieDuration::seconds(0))
        .build();

    let jar = jar.add(sid_cookie).add(clear_csrf);
    (jar, Redirect::to("/")).into_response()
}

#[derive(Deserialize)]
struct LogoutForm {
    csrf: String,
}

async fn logout(
    State(app): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<LogoutForm>,
) -> Response {
    // Logout mutates server state, so it carries the same CSRF requirement as login.
    if let Some(sid) = jar.get(COOKIE_SESSION).map(|c| c.value().to_string()) {
        match app.sessions.get(&sid) {
            Some(session) if constant_eq(&session.csrf, &form.csrf) => {
                app.sessions.destroy(&sid);
            }
            Some(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    [(header::CONTENT_TYPE, "text/plain")],
                    "invalid csrf\n",
                )
                    .into_response();
            }
            None => return Redirect::to("/login").into_response(),
        }
    }
    let jar = jar.add(
        Cookie::build((COOKIE_SESSION, ""))
            .path("/")
            .max_age(CookieDuration::seconds(0))
            .build(),
    );
    (jar, Redirect::to("/login")).into_response()
}

async fn dashboard(State(app): State<Arc<AppState>>, jar: CookieJar) -> Response {
    let session = match jar.get(COOKIE_SESSION).and_then(|c| app.sessions.get(c.value())) {
        Some(s) => s,
        None => return Redirect::to("/login").into_response(),
    };

    let page = DashboardPage {
        instance: app.cfg.instance.name.clone(),
        user: session.user.clone(),
        csrf: session.csrf.clone(),
        version: VERSION.to_string(),
        baseline: app.cfg.instance.probe.baseline(),
        probe: app.cfg.instance.probe.to_string(),
        ingress: match app.cfg.ingress.mode.as_str() {
            "lan" => format!(
                "lan · http://{}:{}",
                app.cfg.instance.bind, app.cfg.instance.port
            ),
            other => format!(
                "{other} · https://{}",
                app.cfg.ingress.hostname.as_deref().unwrap_or("?")
            ),
        },
        backends: app.cfg.build.backends.join(", "),
        targets: app.cfg.targets.join(", "),
        sessions: app.sessions.count(),
    };
    page.into_response()
}

/// Uniform 404: same body for every unknown path, authenticated or not.
async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, [(header::CONTENT_TYPE, "text/plain")], "not found\n")
        .into_response()
}

fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ------------------------------------------------------------------ middleware

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, name: header::HeaderName, val: &'static str| {
        h.insert(name, HeaderValue::from_static(val));
    };
    // No scripts anywhere: the UI is server-rendered and CSS-only.
    set(
        h,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::REFERRER_POLICY, "no-referrer");
    set(h, header::X_FRAME_OPTIONS, "DENY");
    const PERMISSIONS_POLICY: header::HeaderName =
        header::HeaderName::from_static("permissions-policy");
    set(h, PERMISSIONS_POLICY, "geolocation=(), microphone=(), camera=()");
    set(h, header::CACHE_CONTROL, "no-store");
    set(
        h,
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000; includeSubDomains",
    );
    res
}

// ------------------------------------------------------------------ serve

pub async fn serve(cfg: Config, secrets: Secrets) -> anyhow::Result<()> {
    let secure_cookies = cfg.ingress.mode != "lan";
    let state = Arc::new(AppState {
        password_hash: secrets.admin_password_hash.clone(),
        sessions: Sessions::default(),
        throttle: Throttle::default(),
        secure_cookies,
        cfg,
    });

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/assets/app.css", get(stylesheet))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/", get(dashboard))
        .fallback(not_found)
        .layer(middleware::from_fn(security_headers))
        .with_state(state.clone());

    let addr = format!("{}:{}", state.cfg.instance.bind, state.cfg.instance.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("cicd {VERSION} listening on http://{addr}");
    if state.secure_cookies {
        println!(
            "ingress mode {} — expecting TLS termination in front",
            state.cfg.ingress.mode
        );
    } else {
        println!("ingress mode lan — open http://{addr}/login to sign in");
    }
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_eq_behaves() {
        assert!(constant_eq("abc", "abc"));
        assert!(!constant_eq("abc", "abd"));
        assert!(!constant_eq("abc", "ab"));
    }
}
