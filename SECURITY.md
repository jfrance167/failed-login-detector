# Security Policy

## Supported version

Only the latest commit on `main` is maintained.

## Intended use

This repository is an educational defensive-security detector. It is not a
production SIEM. Published log samples are synthetic; real authentication logs
must be treated as sensitive evidence.

## Reporting a security issue

Use GitHub private vulnerability reporting when available. Do not place real
credentials, tokens, usernames, host data, or log evidence in a public issue.
If a real credential is exposed, revoke and rotate it before repository cleanup.

## Maintainer checks

Before publishing, run `pre-commit run --all-files`, the documented test suite,
and GitHub secret scanning. Review and sanitize all added log files.
