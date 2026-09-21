# **Security Policy**

Known Systems AI, Inc. takes the security of this project seriously. This document explains how to report vulnerabilities and what you can expect from us in return.

## **Supported Versions**

| Version | Supported |
| :---- | :---- |
| Latest tagged minor release | ✅ |
| Earlier minor releases | ❌ |

## **Reporting a Vulnerability**

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.**

Report privately through one of the following:

- **GitHub Security Advisories**: if the **"Report a vulnerability"** button is available under
  this repository's **Security** tab, use it to open a private advisory.
- **Email**: `security@dnsid.ai`

## **Our Commitment**

When you report a vulnerability responsibly, we will:

- **Acknowledge** receipt within **3 business days**.  
- Provide an **initial assessment** (validity, severity, next steps) within **14 days**.

## **How Fixes Are Released**

A published package cannot be recalled, so the remedy for a confirmed vulnerability is always a new
version plus an advisory:

1. The fix ships as a new tagged release of the affected project, with its SBOM attached. Where the
   fix is small it is released as a patch on the latest minor so upgrading does not pull in unrelated changes.
2. A GitHub Security Advisory is published on the affected repository at the same time, naming the
   affected range and the first fixed version. A CVE is requested through GitHub for issues rated
   Medium or above. Package registries and Dependabot pick advisories up automatically; there is no
   separate mailing list.
3. Reporters are credited in the advisory unless they ask otherwise.

A report showing an invalid record, signature, or status being **accepted as valid** is treated as the
highest priority regardless of its CVSS score.

## **Remediation Timelines and Support Period**

Beyond the acknowledgement and assessment commitments above, we do not currently commit to fixed
remediation deadlines or to a defined security-support period. Security fixes are provided for the
latest tagged minor release on a best-effort basis. This position will be revisited; any change will be
made in this file first.

## **End of Life**

If maintenance of a project ends, we will say so in its README and a final release note, mark the
package deprecated on its registry with a pointer to any successor, and archive the repository
read-only rather than delete it so that existing installs keep resolving. Forks remain free to continue
under the Apache-2.0 license.

## **Support**

This is open-source software provided under the Apache License 2.0 without warranty. Issues and pull
requests are triaged on a best-effort basis by the maintainers listed in `CODEOWNERS`. No commercial
support is attached to these repositories.

## **Safe Harbor**

We will not pursue or support legal action against researchers who:

- Act in good faith and in accordance with this policy,  
- Avoid privacy violations, service disruption, and destruction/exfiltration of data beyond what is needed to demonstrate the issue, and  
- Give us a reasonable time to respond before disclosing.

*This policy applies to this open-source project only. It does not create any obligation with respect to Known Systems' commercial products or services.*
