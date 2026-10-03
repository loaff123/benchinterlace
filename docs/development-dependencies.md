# Development environment evidence

Runtime dependencies: Python standard library only. The source and tests contain no vendored third-party code or datasets.

Already-installed optional/reference tooling used for validation:

- SciPy 1.17.0 and NumPy 2.3.5: upstream project code uses BSD-3-Clause licenses, verified from installed distribution license text (redistribution, binary-notice and non-endorsement clauses). Binary distributions also bundle separately licensed components; no binaries are redistributed here
- setuptools 84.0.0 and wheel 0.48.0: installed metadata declares MIT; used to build artifacts, not imported by the runtime package
- jsonschema 4.26.0: installed metadata declares MIT; optional schema-checking environment tool, not a runtime dependency

The build-system floor is setuptools 77 because the project's string-valued SPDX
`license = "MIT"` metadata uses [PEP 639 support introduced in that release](https://setuptools.pypa.io/en/stable/userguide/license_migration.html). Runtime
Python support and build-backend support are separate requirements. Building with
setuptools 84.0.0 verifies the installed builder, not every allowed builder version;
setuptools 77 itself has not been installed or qualified here.

No package was installed or downloaded for this implementation. Optional SciPy tests require an existing installation and must be explicitly enabled. The tests and integer oracle use only the standard library by default. A later release must separately validate its chosen Python/platform/build matrix and clean installation workflow; extracted wheel/sdist smoke tests in this stage are not an installation claim.
