# MVNO Light proposal site: build and operations notes

This covers the standalone MVNO Light proposal site, how the access gate works,
how the online signing works, and what needs configuring to switch on email
verification.

## What was built

| File | What it is |
|------|-----------|
| `proposal-gct-mvno-light.md` | The proposal text, the source of truth for wording and figures |
| `mvno-light.html` | The proposal site, served at `/mvno-light` |
| `middleware.js` | The access gate for the whole site, plus the signing API |
| `gate.html` | The access code screen, served at `/gate` |
| `tests/run.sh` | Tests for the gate and the signing API |
| `favicon.ico`, `favicon.svg`, `favicon.png`, `apple-touch-icon.png` | Browser and device icons |
| `og-image.png` | Link preview image for WhatsApp, Teams, Slack and email |

The site is linked from the main product suite page at `/`, both in the top
navigation and as a card in the overview grid.

## Two layers of access control

**Layer one, the server side gate.** `middleware.js` runs on every request. A
visitor without the access cookie is redirected to `/gate` and no page HTML is
served to them. The access code is **GCT2026**, checked case insensitively. The
cookie lasts 30 days. Only `/gate`, the favicons and `og-image.png` are served
before authentication, so link previews still render.

The gate page carries GCT Group branding, using the navy and gold taken from
the GCT logo, and names MVNE as the preparer.

How the gate is hardened:

| Measure | What it prevents |
|---------|------------------|
| The code is posted in a form body, never a query string | A code in a URL lands in server logs, browser history and the Referer header sent to the next site |
| The code is compared in constant time | A byte by byte timing difference lets a patient caller recover the code one character at a time |
| Six attempts per address per minute, then a one minute refusal | Turns an automated guessing run into a slow one. The window opens on the first failure and is never extended, and a locked window refuses the correct code too |
| The limiter never fails the route | If anything in it throws, the request is allowed rather than erroring. A gate that 500s is a gate nobody can pass |
| Cookie named `__Host-gct_access`, with HttpOnly, Secure, Path=/ and SameSite=Lax | The `__Host-` prefix binds the cookie to this exact host over HTTPS, so no sibling or parent host can plant one |
| The client address is read from `x-vercel-forwarded-for` | Vercel's edge sets that header itself. `x-forwarded-for` can be appended to by the caller, which would let an attacker choose its own rate limit bucket |
| Gate, unlock and API responses are sent with `Cache-Control: no-store` | Stops a shared cache holding a response meant for one visitor |

Changing the access code means setting `GATE_CODE` in the Vercel project, with
no deploy needed. Rotating `TOKEN` in `middleware.js` signs out every session
already issued.

**Layer two, the confidentiality popup.** The MVNO Light page holds the document
behind a popup until the reader confirms they are authorised by GCT Group, agrees
to keep the contents confidential, and gives their name. The document is blurred
and cannot be interacted with until then. The name and timestamp are attached to
any signature made in that session. The acknowledgement is remembered for the
browser session only, so it is asked again in a new session.

Changing the access code means editing `PIN` in `middleware.js`. Change `TOKEN`
at the same time, which invalidates every cookie already issued.

## Online signing

Signing runs in five steps, in the manner of a bank's online signing flow.

| Step | What happens |
|------|-------------|
| 1 | The signatory selects what GCT Group is accepting. The MVNO Light platform is fixed as the base. Value added services are optional and the once off and monthly totals update as they are picked |
| 2 | Signatory name, position, organisation, email and optional mobile number, plus a confirmation of authority to sign |
| 3 | Identity verification, either an email code or a personal confirmation, depending on configuration |
| 4 | A drawn or typed signature, plus three consent statements covering the proposal, the conditions precedent and the intent to be bound electronically |
| 5 | The signing certificate |

### What the certificate records

- A SHA 256 hash of the document text exactly as it was displayed to the signatory.
- The date and time of signature in UTC.
- Signatory name, position, organisation, email and mobile number.
- The services selected, with the once off and monthly totals.
- The verification method used.
- The name and timestamp from the confidentiality popup.
- An HMAC SHA 256 signature over all of the above, computed on the server.

The certificate downloads as a self contained HTML file and as a JSON data file.
A copy is emailed to MVNE and to the signatory when email delivery is configured.
The signature also appears in Section 11 of the page itself, so it prints with the
document.

### Verifying a record later

The record signature is an HMAC SHA 256 over this string, with the fields joined
by the pipe character and taken from the certificate:

```
gct-mvno-light-v1|<document hash>|<name>|<position>|<organisation>|<email in lower case>|<signed at>|<verification method>|<comma separated service ids>|<once off>|<monthly>
```

Recomputing it with the same `SIGNING_SECRET` reproduces the signature. Any change
to the document, the signatory or the accepted scope produces a different value,
which is what makes the record tamper evident.

## Configuration

Set these in the Vercel project under Settings, then Environment Variables.

| Variable | Effect if unset | Effect if set |
|----------|-----------------|---------------|
| `GATE_CODE` | The access code is GCT2026 | The access code becomes this value, with no deploy needed |
| `SIGNING_SECRET` | **Signing is refused with a 503.** There is no fallback secret, because a fallback is a secret that sits in the repository | Signing works and records stay verifiable across deployments. Set this before the proposal goes to GCT Group |
| `RESEND_API_KEY` | Email verification is off and the ceremony falls back to a personal confirmation. Certificates are not emailed | Email verification is required before signing, and certificates are emailed |
| `SIGN_FROM_EMAIL` | Same as above, both this and the API key are needed | The from address on outbound email, on a domain verified with the mail provider |
| `SIGN_NOTIFY_EMAIL` | Certificates go to edwardw@mvne.co.za | Certificates go to this address instead |

The page asks the server which verification methods are available and adjusts
step 3 accordingly, so no page change is needed when the variables are added.

**One item to verify before relying on email.** Delivery uses the Resend API at
`https://api.resend.com/emails` with a bearer token and a JSON body of `from`,
`to`, `subject`, `html` and `attachments`. Check that against the current Resend
documentation before switching it on, since the request shape has not been tested
against the live service. Everything else is covered by the tests.

## Security headers

`vercel.json` serves these on every response:

| Header | Value |
|--------|-------|
| Content-Security-Policy | `default-src 'self'`, with scripts limited to the page itself and the Tailwind CDN, styles to the page and Google Fonts, connections to this origin only, and `frame-ancestors 'none'` |
| Strict-Transport-Security | Two years, including subdomains |
| X-Content-Type-Options | nosniff |
| X-Frame-Options | DENY |
| Referrer-Policy | no-referrer |
| Permissions-Policy | Camera, microphone, location, payment and USB all refused |
| X-Robots-Tag | noindex, nofollow, noarchive, nosnippet |
| Cross-Origin-Opener-Policy | same-origin |

The policy still allows inline scripts, because both pages use inline handlers
and inline script blocks. `connect-src 'self'` is the line doing the most work:
it means a script injected into a page cannot post what it reads to another
host.

## The PDF for signature

The PDF is produced by the browser's own print to PDF, driven by a print
stylesheet, so it needs no server side rendering. The PDF button in the header
and the buttons in Section 11 both call it. The output runs to about 22 A4 pages
and carries wet ink signature blocks for both parties in Section 11.

The print stylesheet drops the navigation, the popup and the signing dialog,
lifts the faint text on the navy sections to a readable contrast, keeps cards
whole across page boundaries, and lets long tables flow across pages.

When the proposal has been signed online in the same session, the signature and
its certificate details print inside Section 11.

## Running the tests

```bash
./tests/run.sh
```

35 tests cover the gate, the signing API, and the one time code flow. They
include the rate limiter, refusal of a code sent in a query string, tamper
detection on the verification token, address matching, code expiry,
reproducibility of the record signature, and the refusal to sign at all when
`SIGNING_SECRET` is unset. The tests stub the Vercel import and the mail
provider, so they need no network and no Vercel runtime.

## Known limits

- Signatures are not stored in a database. The record is emailed and downloaded.
  A signature made while email delivery is unconfigured exists only in the
  downloaded files, and the certificate says so on its face.
- The access code is shared rather than per person, so the gate identifies GCT
  Group rather than an individual. The confidentiality popup and the signing
  steps carry the individual detail.
- Attempts are counted in memory, per edge instance, because an edge middleware
  has no shared store. A caller spread across many Vercel regions gets more than
  six attempts a minute in total. It still turns a fast guessing run into a slow
  one, and the code is not short.
- `crypto.subtle` is needed for the document hash and is only available over
  HTTPS or on localhost. On the Vercel deployment this is always the case.
