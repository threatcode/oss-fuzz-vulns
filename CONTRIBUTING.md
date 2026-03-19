# How to Contribute

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

## Automated Workflows

This repository includes automated workflows to keep the vulnerability database up-to-date:

### Daily Update Workflow
- **Schedule**: Runs daily at 2:00 AM UTC
- **Purpose**: Automatically fetches new vulnerabilities from OSV and creates pull requests
- **Actions**:
  - Checks for new OSS-Fuzz vulnerabilities from the OSV API
  - Imports failed bisection vulnerabilities that can be resolved
  - Validates all vulnerability files against the OSV schema
  - Creates automated pull requests for updates

### Weekly Maintenance Workflow
- **Schedule**: Runs weekly on Sundays at 3:00 AM UTC
- **Purpose**: Performs repository maintenance and cleanup
- **Actions**:
  - Checks for duplicate vulnerabilities
  - Validates all vulnerability files
  - Generates repository statistics
  - Identifies outdated vulnerabilities
  - Updates README with latest statistics

Both workflows can be triggered manually via the GitHub Actions interface.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution;
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Code reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

## Community Guidelines

This project follows
[Google's Open Source Community Guidelines](https://opensource.google.com/conduct/).
