// End-to-end walk through the PassAuth web vault.
import { writeFileSync } from "node:fs";
import { launch, sleep } from "./cdp.mjs";

const OUT = process.argv[2];
const BASE = process.env.PASSAUTH_URL ?? "http://localhost:8091";
const EMAIL = `e2e${Date.now()}@example.com`;
const PW = "correct horse battery staple 42";
const b = await launch();
const step = async (name, fn) => {
  process.stdout.write(`- ${name} … `);
  const t = Date.now();
  await fn();
  console.log(`ok (${Date.now() - t} ms)`);
};

try {
  await step("register", async () => {
    await b.goto(`${BASE}/#/register`);
    await b.waitText("Create your PassAuth account");
    await b.screenshot(`${OUT}/01-register.png`);
    await b.fill("Email", EMAIL);
    await b.fill("Your name", "Fahed Test");
    await b.fill("Master password", PW);
    await b.fill("Confirm master password", PW);
    await b.click("button", "Create account");
    await b.waitText("Your vault is ready", 60000);
    await b.click("button", "Open my vault");
    await b.waitFor(`!!document.querySelector('.list-pane')`, 60000);
    await b.screenshot(`${OUT}/02-empty-vault.png`);
  });

  await step("create login with TOTP", async () => {
    await b.goto(`${BASE}/#/vault/all/new-login`);
    await b.waitText("New login");
    await b.fill("Name", "GitHub");
    await b.fill("Username", "octocat");
    await b.fill("Password", "Hunter2-Very-Secret!");
    await b.fill("Authenticator key (TOTP)", "JBSWY3DPEHPK3PXP");
    await b.fill("Website", "https://github.com");
    await b.click("button", "Save item");
    await b.waitFor(`!!document.querySelector('.totp-code')`);
    await b.screenshot(`${OUT}/03-item-detail.png`);
  });

  await step("import Bitwarden CSV", async () => {
    const csv = `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Work,1,login,Jira,,,0,https://jira.example.com,fahed,pw1,
Work,,login,Mail,,,0,https://mail.example.com,fahed@example.com,pw2,
,,note,Wi-Fi,Network: home,,0,,,,
`;
    const path = `${OUT}/bitwarden.csv`;
    writeFileSync(path, csv);
    await b.goto(`${BASE}/#/import`);
    await b.waitFor(`!!document.querySelector('input[type=file]')`);
    await b.setFile("input[type=file]", path);
    await b.waitText("3", 10000);
    await sleep(500);
    await b.screenshot(`${OUT}/04-import-preview.png`);
    const btn = await b.evaluate(`[...document.querySelectorAll('button')].map(b=>b.textContent.trim()).filter(t=>/import/i.test(t)).join(' | ')`);
    console.log(`\n    import buttons: ${btn}`);
    await b.evaluate(`[...document.querySelectorAll('button')].filter(b=>/^Import/.test(b.textContent.trim())).pop().click()`);
    await b.waitFor(`document.body.innerText.match(/imported|added|saved/i)`, 30000);
    await b.screenshot(`${OUT}/05-import-done.png`);
    await b.goto(`${BASE}/#/vault/all`);
    await b.waitText("Jira");
    await b.screenshot(`${OUT}/06-vault-list.png`);
  });

  await step("generator + settings pages render", async () => {
    await b.goto(`${BASE}/#/generator`);
    await sleep(800);
    await b.screenshot(`${OUT}/07-generator.png`);
    await b.goto(`${BASE}/#/settings/security`);
    await sleep(800);
    await b.screenshot(`${OUT}/08-settings-security.png`);
    await b.goto(`${BASE}/#/settings/two-step`);
    await sleep(800);
    await b.screenshot(`${OUT}/09-settings-2fa.png`);
  });

  await step("lock and unlock", async () => {
    await b.goto(`${BASE}/#/vault/all`);
    await b.waitText("Jira");
    await b.click(".sidebar button", "Lock");
    await b.waitText("Your vault is locked");
    await b.screenshot(`${OUT}/10-locked.png`);
    await b.fill("Master password", PW);
    await b.click("button", "Unlock");
    await b.waitText("Jira", 60000);
  });

  await step("sign out and sign in", async () => {
    await b.click(".sidebar button", "Sign out");
    await b.waitText("Sign in to PassAuth");
    await b.fill("Master password", "wrong password here");
    await b.click("button", "Sign in");
    await b.waitFor(`!!document.querySelector('.alert-error')`, 60000);
    const err = await b.evaluate(`document.querySelector('.alert-error').textContent`);
    console.log(`\n    wrong password shows: "${err}"`);
    await b.screenshot(`${OUT}/11-login-error.png`);
    await b.fill("Master password", PW);
    await b.click("button", "Sign in");
    await b.waitText("GitHub", 60000);
  });

  await step("admin panel", async () => {
    await b.goto(`${BASE}/#/admin`);
    await sleep(600);
    await b.evaluate(`(() => { const i = document.querySelector('input'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(i,'e2e-admin-token-123'); i.dispatchEvent(new Event('input',{bubbles:true})); i.form?.requestSubmit(); })()`);
    await b.waitText(EMAIL, 15000);
    await b.screenshot(`${OUT}/12-admin.png`);
  });

  await step("mobile layout", async () => {
    await b.send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    await b.goto(`${BASE}/#/vault/all`);
    await b.waitText("GitHub", 30000);
    await b.screenshot(`${OUT}/13-mobile-list.png`);
  });
  console.log("ALL STEPS PASSED");
} catch (e) {
  console.log(`\nFAILED: ${e.message}`);
  await b.screenshot(`${OUT}/failure.png`).catch(() => {});
} finally {
  if (b.logs.length) console.log("browser console:\n  " + b.logs.join("\n  "));
  await b.close();
}
