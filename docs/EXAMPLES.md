# Zetrix VC MCP Server — Usage Examples

Real-world conversation flows showing how users interact with the MCP server through an AI agent (Claude Desktop, Claude Code, Cursor, etc.). The agent picks the right tool, discovers what's needed, and only asks the user for what it can't resolve on its own.

---

## Example 1 — Issue a VC to yourself (default holder)

> **You:** please apply VC for me

The agent calls the tool with no arguments to discover the required fields.

> **Agent:** I need your Full Name, IC Number, and MyDigitalID Expiry Date.

> **You:** Ahmad bin Abdullah, 900101-01-1234, 2030-01-01

> **Agent:** Done! Your MyKAD credential has been issued.
>
> - **VC ID:** `did:zid:a7fb3289…ea5e1d`
> - **Valid until:** 2027-04-15
> - **Saved to:** `~/Downloads/mykad-a7fb32898f6a.json`

---

## Example 2 — Issue a VC to a specific holder (by address)

> **You:** please issue VC to ZTX3MyCKa7k9Vx5HRR9xju1NKNZyqqQB8Nh6f

> **Agent:** I can't use a Zetrix address directly — could you give me their DID (`did:zid:…`), public key, or private key?

> **You:** here is the public key: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2

> **Agent:** Got it. I also need the holder's Full Name, IC Number, and MyDigitalID Expiry Date.

> **You:** Ali Hassan, 880201-01-5678, 2030-06-15

> **Agent:** Done! The MyKAD credential has been issued to the holder.
>
> - **VC ID:** `did:zid:5c8e2f91…b3a720`
> - **Holder DID:** `did:zid:a1b2c3d4…f6a1b2`
> - **Valid until:** 2027-04-15

---

## Example 3 — Issue a VC to a holder (by private key)

> **You:** issue VC to this holder, private key is privBtEXDaYDWH9QV4xQEkmokedbtQrggRZQtKGpt9uXttLA2v3fCC8v

> **Agent:** I need the holder's Full Name, IC Number, and MyDigitalID Expiry Date.

> **You:** Jalil Rashid, 870102-01-2233, 2030-12-31

> **Agent:** Done! The MyKAD credential has been issued.
>
> - **VC ID:** `did:zid:972485c6…042d6a`
> - **Holder DID:** `did:zid:56db08df…b9c39e`
> - **Valid until:** 2027-04-15

---

## Example 4 — Issue a VC to a holder (by DID)

> **You:** please create VC for did:zid:56db08df6a7db46e91495f239eccb537bed3e4f58bb5daf9a18972ef26b9c39e

> **Agent:** I need the holder's Full Name, IC Number, and MyDigitalID Expiry Date.

> **You:** Siti Aminah, 910315-02-4455, 2031-03-15

> **Agent:** Done! The MyKAD credential has been issued.
>
> - **VC ID:** `did:zid:8b3f7c21…e495a1`
> - **Holder DID:** `did:zid:56db08df…b9c39e`
> - **Valid until:** 2027-04-15

---

## Example 5 — Create a VP (Verifiable Presentation)

After receiving a VC, the holder can create a VP to share selectively with a verifier.

> **You:** please create VP from the VC I just received, reveal only the name

> **Agent:** Done! Your Verifiable Presentation has been created.
>
> - **Disclosed fields:** Name only (IC Number and Expiry are hidden)
> - **Share token:** `v2-c3f91cab-b635-4b50-aaef-dae986b7532d`
>
> You can share this token with a verifier — they have ~30 seconds to verify it, or you can send them the full VP file directly.

What the verifier sees (only the disclosed field):
```json
{
  "credentialSubject": {
    "mykad": {
      "name": "Jalil Rashid"
    }
  }
}
```

> The IC number and expiry date are **cryptographically hidden** via BBS+ selective disclosure — the verifier cannot recover them.

---

## Example 6 — Verify a VP (by share token)

A verifier who received a share token can check it:

> **You:** please verify this VP: v2-c3f91cab-b635-4b50-aaef-dae986b7532d

> **Agent:** The presentation is **valid** ✓
>
> | Field | Value |
> |---|---|
> | Issuer | `did:zid:ba12fe05…ae9e3e6d` |
> | Valid from | 2026-04-13 |
> | Valid until | 2027-04-15 |
> | Disclosed claims | `name: "Jalil Rashid"` |
>
> No errors. The credential has not been revoked.

---

## Example 7 — Verify a VP (by VP file / object)

If the share token has expired (~30s server-side TTL), the verifier can verify the full VP directly:

> **You:** please verify this VP *(paste VP JSON or reference a file)*

> **Agent:** The presentation is **valid** ✓
>
> Same result as above — verification works indefinitely against the full VP object, unlike the time-limited share token.

---

## Example 8 — Revoke a VC

An issuer can permanently revoke a VC:

> **You:** please revoke this VC: did:zid:972485c6e9d898afc9d235b492f2420b0410832e790ab69f679ac6ed9c042d6a

> **Agent:** ⚠️ This action is permanent and cannot be undone. Are you sure you want to revoke this credential?

> **You:** yes

> **Agent:** Done. The credential has been revoked.
>
> - **VC ID:** `did:zid:972485c6…042d6a`
> - **On-chain TX:** `7880733ff3d80c92…`
> - **Revoked at:** 2026-04-13 16:32:59

---

## Example 9 — Check revocation status

> **You:** is this VC revoked? did:zid:972485c6e9d898afc9d235b492f2420b0410832e790ab69f679ac6ed9c042d6a

> **Agent:** Yes — this credential was **revoked** on 2026-04-13 at 16:32:59.

---

## Example 10 — Look up template requirements

> **You:** what fields does the MyKAD template need?

> **Agent:** The MyKAD template requires:
>
> | Field | Label | Format |
> |---|---|---|
> | `name` | Name | String |
> | `icNo` | IC Number | String |
> | `expiry` | MyDigitalID Expiry Date | String |

---

## Example 11 — Generate / look up a DID

> **You:** what is my DID?

> **Agent:** Your holder DID is: `did:zid:55af306a2a1e7edcd95587a6505cc5c783bbdeec1c69f59fc90de5fa6bd72d64`

---

## Key Behaviours

### What the agent does automatically (you never need to mention these)
- Discovers the template's required fields by probing the tool
- Derives the holder DID from the configured private key
- Signs all requests (apply, issue, download, VP, revocation) locally with Ed25519
- Defaults `validUntil` to +1 year
- Saves the downloaded VC as a `.json` file in `~/Downloads`
- Retries the download step if the server needs a moment after issuance (eventual consistency)

### What the agent will ask you for
- **Claim values** (name, IC number, etc.) — only after discovering the template's fields
- **Holder identity** — only when you specify a recipient who isn't the configured default (DID, public key, or private key — never a ZTX3 address)
- **Confirmation** — before destructive actions like revocation

### What the agent should never say to you
- Tool names (`zetrix_vc_issue`, `zetrix_vp_present`, etc.)
- Parameter names, JSON, API endpoints, internal flow steps
- Environment variable names (`HOLDER_PRIVATE_KEY`, `DEFAULT_TEMPLATE_ID`, etc.)
- Which step in a multi-step flow is currently running
