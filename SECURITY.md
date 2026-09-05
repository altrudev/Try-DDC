# Security

Try DDC is intentionally designed as a non-executing static review tool.

## Trust boundary

The analyzer must not:

- execute target-repository code;
- install target dependencies;
- run target build, test, package, installer, or workflow scripts;
- upload target source to DDC Assurance Lab;
- require write permission to the target repository;
- require persisted GitHub checkout credentials.

The recommended GitHub workflow grants only `contents: read` and uses `persist-credentials: false` during checkout.

## Reporting a security issue

Do not publish exploitable details in a public issue if the issue could expose users running Try DDC.

Contact: security@ddcal.ca

Public information: https://ddcal.ca/security.html

## Result boundary

A Try DDC result is a bounded review artifact. It is not certification, an accredited result, a penetration test, a security guarantee, or authorization to execute the analyzed repository.
