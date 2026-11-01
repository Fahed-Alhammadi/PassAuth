//! Transactional email over SMTP. With no SMTP configured, mail is logged
//! (subject only) and dropped, and features that need it are disabled.

use anyhow::{Context, Result};
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::{Config, SmtpConfig, SmtpSecurity};

pub struct Mailer {
    transport: Option<(AsyncSmtpTransport<Tokio1Executor>, Mailbox)>,
    domain: String,
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
    pub fn new(config: &Config) -> Result<Self> {
        let transport = config.smtp.as_ref().map(build).transpose()?;
        Ok(Self {
            transport,
            domain: config.domain.clone(),
        })
    }

    pub fn enabled(&self) -> bool {
        self.transport.is_some()
    }

    pub async fn send(&self, to: &str, email: Email) -> Result<()> {
        let Some((transport, from)) = &self.transport else {
            tracing::info!(subject = %email.subject, "SMTP not configured; email not sent");
            return Ok(());
        };
        let msg = Message::builder()
            .from(from.clone())
            .to(to.parse().context("invalid recipient address")?)
            .subject(&email.subject)
            .multipart(MultiPart::alternative_plain_html(
                render_text(&email, &self.domain),
                render_html(&email, &self.domain),
            ))?;
        transport.send(msg).await.context("sending email")?;
        Ok(())
    }

    /// Send in the background; failures are logged, never surfaced to the requester.
    pub fn send_later(self: &std::sync::Arc<Self>, to: String, email: Email) {
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
        smtp.from.parse().context("SMTP_FROM")?,
    );
    Ok((builder.build(), from))
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
