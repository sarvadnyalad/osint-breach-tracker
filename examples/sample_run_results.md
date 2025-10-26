# Data Breach & Credential Exposure – Findings

Generated: `2025-10-26T18:21:38.780491Z`

- **Total exposed accounts:** 9
- **Unique emails:** 9
- **Distinct breaches:** 7
- **Overall risk score:** 4.67 (High)

## Top Breaches by Severity

- **NewSaaS** — 2 records | 2 emails | Avg severity: 5.0 (High) | Latest: 2025-01-15
- **Acme-Partner** — 1 records | 1 emails | Avg severity: 5.0 (High) | Latest: 2024-08-03
- **PhotoApp** — 1 records | 1 emails | Avg severity: 5.0 (High) | Latest: 2023-05-09
- **ShopLeak** — 1 records | 1 emails | Avg severity: 5.0 (High) | Latest: 2021-02-10
- **TravelDB** — 1 records | 1 emails | Avg severity: 5.0 (High) | Latest: 2019-11-21
- **DevPaste** — 2 records | 2 emails | Avg severity: 4.0 (High) | Latest: 2022-07-19
- **OldForum** — 1 records | 1 emails | Avg severity: 4.0 (High) | Latest: 2016-05-02

## Exposure Types (Examples)

| email           | source       | breach_date   | compromised_data                    |
|:----------------|:-------------|:--------------|:------------------------------------|
| alice@acme.test | OldForum     | 2016-05-02    | email; username; password           |
| bob@acme.test   | TravelDB     | 2019-11-21    | email; password; phone              |
| carol@acme.test | ShopLeak     | 2021-02-10    | email; password_hash; address       |
| dave@acme.test  | DevPaste     | 2022-07-19    | email; username; password           |
| erin@acme.test  | Acme-Partner | 2024-08-03    | email; password; name               |
| grace@acme.test | NewSaaS      | 2025-01-15    | email; password; 2fa_backup_codes   |
| harry@acme.test | NewSaaS      | 2025-01-15    | email; password                     |
| ian@acme.test   | PhotoApp     | 2023-05-09    | email; username; password_hash; dob |
| jane@acme.test  | DevPaste     | 2022-07-19    | email; username; password           |

---
**Note:** This report uses an offline sample dataset for demonstration. Live enrichment via HIBP can be enabled with an API key.