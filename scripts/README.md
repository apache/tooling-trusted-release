# ATR utility scripts

Many of these scripts are intended to be used by other scripts, or by `Makefile` targets.

## build

Builds a Docker image for the application. Accepts optional Dockerfile path (default `Dockerfile.alpine`) and image tag (default `tooling-trusted-releases`) arguments.

## check\_user.py

Reports committee memberships for an ASF user. Takes a username as an argument and displays which committees the user is a member of and which committees the user is a participant of. Useful for debugging authorisation issues.

## docs\_build.py

Generates navigation headers for documentation files. Reads the table of contents from `atr/docs/index.md` and rewrites each documentation file with a heading and navigation block (Up/Prev/Next/Pages/Sections) based on the TOC structure.

## docs\_check.py

Validates internal documentation links. Scans Markdown files in `atr/docs/` to ensure links point to existing files and that anchor fragments match heading IDs. Returns a non-zero exit code if validation fails.

## docs\_post\_process.py

Adds heading IDs to HTML documentation files. Processes CommonMark-generated HTML to add `id` attributes to headings that lack them, deriving IDs from the heading text after stripping leading section numbers.

## extract\_spdx\_identifiers.py

Extracts SPDX license identifiers from an HTML license list. Parses anchor `title` attributes to collect identifiers categorised as A, B, or X, and outputs the results as JSON.

## generate-certificates

Generates self signed SSL certificates for development and testing purposes. It creates a private RSA key and a certificate valid for `127.0.0.1` with a one year expiration period, and stores them in the state directory as `cert.pem` and `key.pem`.

## github\_tag\_dates.py

Retrieves CycloneDX Maven Plugin release dates from GitHub. Queries the GitHub GraphQL API for tags prefixed with `cyclonedx-maven-plugin-` and outputs a JSON mapping of commit dates to version numbers.

## integrity\_check.py

Validates the integrity of all data in the ATR database. Runs validation checks across all stored data and reports any divergences or errors found.

## interface\_order.py

Checks that Python module interfaces are alphabetically ordered. Verifies that top-level functions and classes are defined in alphabetical order, reports private class names (those starting with `_`), and flags misordered definitions.

## interface\_privacy.py

Detects external access to private interfaces in Python modules. Reports any accesses to single underscore attributes (e.g. `obj._private_attr`) where the object is not `self` or `cls`.

## keys\_import.py

Imports OpenPGP public keys from ASF committee KEYS files into the ATR database. Downloads each committee's `KEYS` file from `https://downloads.apache.org/{committee}/KEYS`, parses the keys, and updates the database. Logs all activity to `state/keys_import.log`.

## lint/jinja\_route\_checker.py

Validates that Jinja templates only reference routes that exist. Scans all templates in `atr/templates/` for `as_url(routes.<name>)` calls and reports any references to routes not found in `state/routes.json`.

## release\_path\_parse.py

Analyses release artifact path patterns from Apache distribution repositories. Reads a list of paths and applies heuristic parsing to identify components (`ASF`, `CORE`, `SUB`, `VERSION`, `VARIANT`, `TAG`, `ARCH`, `EXT`, and optionally `LABEL`), outputting a summary of detected patterns grouped by project.

Excerpt from example output:

```
--- age ---

  VERSIONS: 1.1.0, 1.5.0
  SUBS: PG11, PG12, PG13, PG14, PG15, PG16, age-viewer

   21 ASF-CORE-VERSION-VARIANT.EXT
    3 ASF-SUB-TAG-rc2-incubating-VARIANT.EXT


--- airavata ---

  VERSIONS: 0.17, 1.1
  SUBS: custos

    8 ASF-CORE-SUB-VERSION-VARIANT.EXT
    6 ASF-CORE-server-VERSION-VARIANT.EXT
    3 CORE-VERSION-VARIANT.EXT
    5 SUB-VERSION-VARIANT.EXT
```

## vote\_initiate\_convert.py

Upgrades legacy vote initiation task results to the current format. Queries the database for `vote_initiate` tasks, converts legacy JSON formats to the current `VoteInitiate` model, and commits the upgraded results.
