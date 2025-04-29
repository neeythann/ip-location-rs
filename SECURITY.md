# Responsible Disclosure Policy

We welcome the responsible disclosure of security vulnerabilities. Please adhere to the following guidelines:

- Do not disclose vulnerabilities publicly until they have been addressed.
- Report vulnerabilities privately using the repository’s security advisories feature.
- Provide as much detail as possible, including:
  - A description of the vulnerability.
  - Steps to reproduce the issue.
  - Any known workarounds or mitigations.

We will acknowledge your report within 3 business days and keep you informed of our progress. Once a fix is released, we will credit contributors as appropriate via the release notes (unless anonymity is requested).

## Supported versions

All versions including and above the current stable relase version number

## Reporting a vulnerability

The private vulnerability reporting feature for this repository is enabled. We kindly ask to not use the public issues board to report a security vulnerability.
Additionally, please do not contact a maintainer outside of the said instructions to report a vulnerability.

## Out of scope vulnerabilities

The following bug classes are out of scope:
- Missing security best practices that do not directly lead to a vulnerability
- Issues in an upstream software dependency
- (Distributed) Denial of Service

## Considerations

The index endpoint of this microservice is meant to be deployed within a reverse proxy. Deploying it direcly makes it vulnerable to [HTTP Header Injection](https://en.wikipedia.org/wiki/HTTP_header_injection) attacks,
which is currently not (and will not be) supported anytime in the future

