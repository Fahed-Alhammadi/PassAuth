//! Transactional email over SMTP. With no SMTP configured, mail is logged
//! (subject only) and dropped, and features that need it are disabled.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::{SmtpConfig, SmtpSecurity};

pub struct Mailer {
    /// Current SMTP setup; replaced from the admin page without a restart.
    smtp: std::sync::RwLock<Option<Arc<Smtp>>>,
    domain: String,
}

struct Smtp {
    config: SmtpConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

pub struct Email {
    pub subject: String,
    pub heading: String,
    pub body: String,
    /// Optional call-to-action button.
    pub action: Option<(String, String)>,
    /// Optional large code (verification / 2FA).
    pub code: Option<String>,
}

impl Mailer {
    pub fn new(domain: &str, smtp: Option<&SmtpConfig>) -> Result<Self> {
        let mailer = Self {
            smtp: std::sync::RwLock::new(None),
            domain: domain.to_owned(),
        };
        mailer.configure(smtp)?;
        Ok(mailer)
    }

    /// Use `smtp` from now on (`None` turns email off). On error the old setup stays.
    pub fn configure(&self, smtp: Option<&SmtpConfig>) -> Result<()> {
        let next = smtp
            .map(|c| {
                build(c).map(|(transport, from)| {
                    Arc::new(Smtp {
                        config: c.clone(),
                        transport,
                        from,
                    })
                })
            })
            .transpose()?;
        *self.smtp.write().expect("smtp lock") = next;
        Ok(())
    }

    fn current(&self) -> Option<Arc<Smtp>> {
        self.smtp.read().expect("smtp lock").clone()
    }

    /// The SMTP setup in use, if any.
    pub fn config(&self) -> Option<SmtpConfig> {
        self.current().map(|s| s.config.clone())
    }

    pub fn enabled(&self) -> bool {
        self.smtp.read().expect("smtp lock").is_some()
    }

    pub async fn send(&self, to: &str, email: Email) -> Result<()> {
        let Some(smtp) = self.current() else {
            tracing::info!(subject = %email.subject, "SMTP not configured; email not sent");
            return Ok(());
        };
        let msg = Message::builder()
            .from(smtp.from.clone())
            .to(to.parse().context("invalid recipient address")?)
            .subject(&email.subject)
            .multipart(MultiPart::alternative_plain_html(
                render_text(&email, &self.domain),
                render_html(&email, &self.domain),
            ))?;
        smtp.transport.send(msg).await.context("sending email")?;
        Ok(())
    }

    /// Plain TCP connection to every address the SMTP host resolves to, for the admin's
    /// test. The SMTP client reports only the last address's error, which inside Docker is
    /// often an IPv6 "network unreachable" that hides why the IPv4 address failed.
    pub async fn check_connection(&self) -> Option<String> {
        let smtp = self.current()?;
        let (host, port) = (&smtp.config.host, smtp.config.port);
        let addrs = match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(a) => a.collect::<Vec<_>>(),
            Err(e) => return Some(format!("{host} could not be resolved: {e}.")),
        };
        let mut results = Vec::new();
        for addr in addrs {
            let r =
                tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
                    .await;
            results.push((
                addr,
                r.map_err(|_| None).and_then(|r| r.map(drop).map_err(Some)),
            ));
        }
        Some(describe(host, port, &results))
    }

    /// Send in the background; failures are logged, never surfaced to the requester.
    pub fn send_later(self: &Arc<Self>, to: String, email: Email) {
        let mailer = self.clone();
        tokio::spawn(async move {
            if let Err(e) = mailer.send(&to, email).await {
                tracing::warn!(error = %e, "email delivery failed");
            }
        });
    }
}

fn build(smtp: &SmtpConfig) -> Result<(AsyncSmtpTransport<Tokio1Executor>, Mailbox)> {
    let mut builder = match smtp.security {
        SmtpSecurity::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)?,
        SmtpSecurity::ForceTls => AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)?,
        SmtpSecurity::Off => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host),
    }
    .port(smtp.port);
    if let (Some(u), Some(p)) = (&smtp.username, &smtp.password) {
        builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
    }
    let from = Mailbox::new(
        Some(smtp.from_name.clone()),
        smtp.from.parse().with_context(|| {
            format!(
                "sender address {:?} is not a valid email address",
                smtp.from
            )
        })?,
    );
    Ok((builder.build(), from))
}

/// One address's outcome: connected, failed with an error, or timed out (`Err(None)`).
type Probe = std::result::Result<(), Option<std::io::Error>>;

fn describe(host: &str, port: u16, results: &[(SocketAddr, Probe)]) -> String {
    if results.is_empty() {
        return format!("{host} has no addresses.");
    }
    let parts: Vec<String> = results
        .iter()
        .map(|(addr, r)| match r {
            Ok(()) => format!("{addr} connected"),
            Err(None) => format!("{addr} timed out"),
            Err(Some(e)) => format!("{addr} {e}"),
        })
        .collect();
    let mut out = format!("Connection check: {}.", parts.join("; "));
    let ok = |v6: bool| results.iter().any(|(a, r)| a.is_ipv6() == v6 && r.is_ok());
    let tried = |v6: bool| results.iter().any(|(a, _)| a.is_ipv6() == v6);
    if tried(false) && !ok(false) && !ok(true) {
        out.push_str(&format!(
            " Outgoing connections to port {port} fail. Many VPS providers block mail ports (25, 465, 587) on new servers: ask your provider to allow them, or use another port your mail provider offers (for example 2525)."
        ));
    }
    let v6_unreachable = results.iter().any(|(a, r)| {
        a.is_ipv6()
            && matches!(r, Err(Some(e)) if e.kind() == std::io::ErrorKind::NetworkUnreachable)
    });
    if v6_unreachable {
        out.push_str(" IPv6 isn't available inside the container, which is normal for Docker and only matters if the host has no IPv4 address.");
    }
    out
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_text(e: &Email, domain: &str) -> String {
    let mut out = format!("{}\n\n{}\n", e.heading, e.body);
    if let Some(code) = &e.code {
        out.push_str(&format!("\nCode: {code}\n"));
    }
    if let Some((label, url)) = &e.action {
        out.push_str(&format!("\n{label}: {url}\n"));
    }
    out.push_str(&format!("\n— PassAuth · {domain}\n"));
    out
}

fn render_html(e: &Email, domain: &str) -> String {
    let code = e.code.as_deref().map(|c| {
        format!(
            r#"<p style="font:600 28px/1.2 ui-monospace,Menlo,monospace;letter-spacing:6px;margin:24px 0;color:#0b1f33">{}</p>"#,
            escape(c)
        )
    });
    let action = e.action.as_ref().map(|(label, url)| {
        format!(
            r#"<p style="margin:28px 0"><a href="{}" style="background:#0f62fe;color:#fff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600">{}</a></p>"#,
            escape(url),
            escape(label)
        )
    });
    format!(
        r#"<!doctype html><html><body style="margin:0;background:#f3f5f8;font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;color:#33475b">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="100%" style="max-width:520px;background:#fff;border-radius:12px;padding:32px">
<tr><td>
<p style="font-weight:700;font-size:18px;color:#0b1f33;margin:0 0 24px">&#128274; PassAuth</p>
<h1 style="font-size:20px;color:#0b1f33;margin:0 0 12px">{heading}</h1>
<p style="margin:0">{body}</p>
{code}{action}
<p style="font-size:12px;color:#7a8a99;margin:32px 0 0">Sent by your PassAuth server at {domain}. If you didn't expect this email, you can ignore it.</p>
</td></tr></table></td></tr></table></body></html>"#,
        heading = escape(&e.heading),
        body = escape(&e.body).replace('\n', "<br>"),
        code = code.unwrap_or_default(),
        action = action.unwrap_or_default(),
        domain = escape(domain),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn describes_blocked_ipv4_behind_unreachable_ipv6() {
        let v4: SocketAddr = "192.0.2.10:587".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:587".parse().unwrap();
        let text = describe(
            "smtp.example.com",
            587,
            &[
                (v4, Err(None)),
                (v6, Err(Some(Error::from(ErrorKind::NetworkUnreachable)))),
            ],
        );
        assert!(text.starts_with("Connection check: 192.0.2.10:587 timed out; [2001:db8::1]:587 "));
        assert!(text.contains("block mail ports"));
        assert!(text.contains("IPv6 isn't available"));
        let fine = describe("smtp.example.com", 587, &[(v4, Ok(()))]);
        assert_eq!(fine, "Connection check: 192.0.2.10:587 connected.");
    }
}
