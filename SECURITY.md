# Security policy

kuukura stores secrets, so please report vulnerabilities privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security** tab, choose **Report a
vulnerability**, and describe what you found. Please do not open a public issue or pull request for it.

Helpful to include: the version (`ku-server version`, `ku version`), how to reproduce it, and what an attacker gains.
Use fake secrets and your own instance for testing.

## Supported versions

Only the **latest release** (tags are `YEAR.MONTH.N`) gets security fixes. Older releases are not patched: upgrade.

## What to expect

kuukura is maintained by one person, so these are targets, not guarantees:

- an acknowledgement within **5 working days**;
- an assessment (accepted, need more information, or not a vulnerability) within **14 days**;
- a fix or a mitigation for a confirmed issue, depending on severity, usually within **90 days**, and sooner for
  anything that exposes secret values. Reporters are credited in the release notes unless they prefer not to be.

## Scope

In scope: the server (`ku-server`), the CLI (`ku`), the container image and the release artifacts, and the
documented deployment files under `deploy/`.

Out of scope: attacks that need root on the server host or your database administrator (see
[docs/threat-model.md](docs/threat-model.md), "Not defended"), a compromised user device, social engineering,
denial of service by sheer volume, and weaknesses in your reverse proxy, Google account or DNS.

## Safe harbor

If you act in good faith, test only your own instance, avoid other people's data, do not degrade the service for
others and give us reasonable time to fix the issue before disclosing it, we will not pursue legal action over your
research and will work with you on a coordinated disclosure.
