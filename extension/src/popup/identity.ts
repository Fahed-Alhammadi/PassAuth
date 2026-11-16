/**
 * The identity fields the popup shows, in the web vault's order and wording
 * (web/src/pages/Vault.tsx). Numbers that identify a person officially are
 * `secret`: hidden until revealed, like a password. Unit-tested in test/identity.test.ts.
 */
import type { Identity } from "@web/lib/types";

export interface IdentityRow {
  label: string;
  value: string;
  secret: boolean;
}

export function identityRows(i: Identity): IdentityRow[] {
  const rows: IdentityRow[] = [
    { label: "Name", value: [i.title, i.first_name, i.middle_name, i.last_name].filter(Boolean).join(" "), secret: false },
    { label: "Email", value: i.email, secret: false },
    { label: "Phone", value: i.phone, secret: false },
    { label: "Company", value: i.company, secret: false },
    { label: "Address", value: [i.address1, i.address2, i.city, i.state, i.postal_code, i.country].filter(Boolean).join(", "), secret: false },
    { label: "Username", value: i.username, secret: false },
    { label: "National ID", value: i.ssn, secret: true },
    { label: "Passport number", value: i.passport_number, secret: true },
    { label: "Licence number", value: i.license_number, secret: true },
  ];
  return rows.filter((r) => !!r.value);
}
