# Worked example — a marketplace program whose only testable asset is a backend
#
# Source: https://bugcrowd.com/engagements/apps-plus2 (read 2026-10-11)
#
# This is the *paste-in* path, and it is the honest one for this program. The
# page's "In Scope Targets" table lists 45 URLs, and every one of them is an app
# *listing* on marketplace.atlassian.com — no testable host at all. The
# importer recognises that and excludes the marketplace automatically.
#
# The program's own scope text says the testable asset is "the Apps+-operated
# backend functionality they call". That host is not printed on the page, so a
# human has to add it. That is what the marked line below is for.

## In Scope Targets

| Name / Location | Tags | Known issues |
| https://marketplace.atlassian.com/apps/1227541/ai-badges-for-confluence | Website Testing | |
| https://marketplace.atlassian.com/apps/1227543/ai-grammar-for-confluence | Website Testing | |
| https://marketplace.atlassian.com/apps/1229018/ai-photos-for-confluence | Website Testing | |
# VERIFY: replace with the backend host from the program's own scope text.
# Example shape only — do not test a host you have not confirmed:
# | api.appsplus.example.com | API | |

## Out of scope

| Name | Reason |
| appsplus.co | marketing site |
| www.appsplus.co | marketing site |
| docs.appsplus.co | documentation site |
| support.appsplus.co | support site |
| go.appsplus.co | marketing site |
| tabs.appsplus.co | legacy Atlassian Connect host (deprecated) |
| broken-links.appsplus.co | legacy Atlassian Connect host (deprecated) |
| countdown-timer.appsplus.co | legacy Atlassian Connect host (deprecated) |
| gender-bias.appsplus.co | legacy Atlassian Connect host (deprecated) |
| incoming-links.appsplus.co | legacy Atlassian Connect host (deprecated) |
| panel-macro.appsplus.co | legacy Atlassian Connect host (deprecated) |
| search-results.appsplus.co | legacy Atlassian Connect host (deprecated) |
| shortlinks.appsplus.co | legacy Atlassian Connect host (deprecated) |
| speed-reader.appsplus.co | legacy Atlassian Connect host (deprecated) |
| tag-cloud.appsplus.co | legacy Atlassian Connect host (deprecated) |
| update-this.appsplus.co | legacy Atlassian Connect host (deprecated) |
| word-count.appsplus.co | legacy Atlassian Connect host (deprecated) |
| zoom-recordings.appsplus.co | legacy Atlassian Connect host (deprecated) |

## Scope

Test only the listed in-scope apps and the Apps+-operated backend functionality they call. Other Apps+ services, internal/development systems and customer instances are out of scope.
Bypasses of authentication, billing or quota controls are in scope. Prove them in no more than 5 requests, then stop.
Findings whose only impact is cost, volume or load (missing rate limits, denial of wallet) are out of scope.
Prompt injection is out of scope and not bounty-eligible.
Changing prompts, generated text or model behavior is also out of scope.

## Submission eligibility

A human verifies every finding. Unattended mass scanning, bulk submissions and unverified agent output are not allowed.
One report per underlying vulnerability. One root cause earns one bounty across all Apps+ programs.
Publicly disclosed vulnerabilities have a 90-day bounty grace period.
Issues introduced by a new release have a 30-day grace period.
Regressions are not rewarded.

## Testing rules

Use only accounts and data you control.
A human verifies every finding before it is accepted.

## Cost and load limits

5 requests per second, maximum 200 requests.

## Rewards

P1 | $1500
P2 | $900
P3 | $300
P4 | $100
