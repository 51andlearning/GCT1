# GCT Group proposals

Proposal documents and the gated proposal site for engagements between
DSG / MVNE (Pty) Ltd and GCT Group, Nigeria.

## The site

| Route | Page |
|-------|------|
| `/` | Full DSG and MVNE product suite for GCT Group |
| `/mvno-light` | Standalone MVNO Light proposal, with online signing and a PDF for signature |
| `/gate` | Access code screen |

Every route is behind a server side access code. See
[mvno-light-site-notes.md](mvno-light-site-notes.md) for how the gate, the online
signing and the PDF export work, and for the environment variables that switch on
email verification.

## Proposals

| Document | Client | Value |
|----------|--------|-------|
| [MVNO Light](proposal-gct-mvno-light.md) | GCT Group | $20,000 once off, $5,000 per month minimum, 50/50 profit share |
| [DBOT partnership](proposal-gct-dbot.md) | GCT Group | $250,000 fixed fee |
| [Yellow Dot PWA support](proposal-yellowdot-pwa.md) | Yellow Dot | $12,507 once off, $4,250 per month |
| [Yellow Dot travel eSIM](proposal-yellowdot-esim.md) | Yellow Dot | $3,200 once off, 50/50 margin share |

## Tests

```bash
./tests/run.sh
```
