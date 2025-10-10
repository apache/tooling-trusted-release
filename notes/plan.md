# Implementation plan

This is a rough plan of immediate tasks. The priority of these tasks may change, and we may add or drop tasks as appropriate using a reactive development style.

## UX improvements

1. Improve RC workflow
   - [DONE] Allow upload of checksum file alongside artifacts and signatures
   - [DONE] Add a form field to choose the RC artifact type
   - [DONE] Allow extra types of artifact, such as reproducible binary and convenience binary
   - [DONE] Differentiate between podling PPMCs and top level PMCs
   - [DONE] Allow package deletion
   - [DONE] Allow RCs to be deleted
   - [DONE] Move signature verification to a task runner
   - [DONE] Add a method to allow the bulk addition of RC artifacts
   - Improve the existing method to allow the bulk addition of RC artifacts
   - Add further methods to allow the bulk addition of RC artifacts

2. Enhance RC display
   - [DONE] Augment raw file hashes with the original filenames in the UI
   - [DONE] Add file size and upload timestamp
   - [DONE] Improve the layout of file listings
   - [DONE] Show KB, MB, or GB units for file sizes
   - [DONE] Add a standard artifact naming pattern based on the committee and project
   - [DONE] Potentially add the option to upload package artifacts without signatures
   - [DONE] Show validation status indicators
   - [DONE] Add developer RC download buttons with clear verification instructions
   - Make developer RC download buttons public for external developers
   - Improve validation status indicators

3. Improve key management interface
   - [DONE] Display which PMCs are using each key
   - [DONE] Add key expiration warnings
   - [DONE] Fix reported problem with adding keys
   - [DONE] Add debugging output error messages for when key addition fails
   - Allow adding keys from a KEYS file
   - Allow +1 binding voters to have their signatures added to the release

4. Release status dashboard
   - Add progress indicators for release phases
   - Show current blockers and required actions
   - Add quick actions for release managers

5. General website improvements
   - Add orienting style or features to improve navigability

Advanced tasks, possibly deferred
   - Implement a key revocation workflow
   - Check RC file naming conventions
   - Add ability to sign artifact hashes on the platform using JS

## Task scheduler

We aim to work on the task scheduler in parallel with the UX improvements above. Artifact validation and the release status dashboard are dependent on tasks, which are managed by the task scheduler.

1. Task runner workers
   - [DONE] Implement worker process with RLIMIT controls for CPU and RAM
   - [DONE] Implement safe handling for compressed asset expansion
   - [DONE] Test external tool use
   - Track the duration of tasks in milliseconds
   - Add disk usage tracking through API and psutil polling
   - Add rollback or reporting for failed tasks
   - Ensure idempotent operations where possible
   - Consider distinguishing between issue and error states
   - Use consistent task status values (pending, running, passed, issue, error?)
   - Add a warning task result status
   - Allow dependencies between tasks to reduce duplication of effort
   - Add UI to restart all waiting workers

2. Orchestrating manager and resource management
   - [DONE] Implement process-based task isolation
   - [DONE] Create task table in sqlite database
   - [DONE] Add task queue management
   - Track and limit disk usage per task in the manager

3. Improve the task UI
   - [DONE] Allow restarting all tasks when inactive
   - Test that tasks are deleted when a package is deleted

Advanced tasks, possibly deferred
   - Check fair scheduling across cores
   - Add task monitoring and reporting

## Site improvements

1. Fix bugs and improve workflow
   - [DONE] Add ATR commit or version number to the UI
   - [DONE] Fix and improve the package checks summary count
   - [DONE] Improve the proprietary platform patch in ASFQuart
   - [DONE] Ensure that all errors are caught and logged or displayed
   - Add further tests
   - Decide whether to use Alembic and, if not, remove `alembic.cfg`

2. Ensure that performance is optimal
   - [DONE] Add page load timing metrics to a log
   - [DONE] Add a basic metrics dashboard

3. Increase the linting, type checking, and other QA
   - [DONE] Potentially add blockbuster
   - Create website UX integration tests using a browser driver

Advanced tasks, possibly deferred
   - Patch the synchronous behaviour in Jinja and submit upstream

## Basic RC validation

These tasks are dependent on the task scheduler above.

1. Basic artifact validation
   - [DONE] Implement basic archive verification
   - [DONE] Implement basic signature verification

2. License compliance
   - [DONE] Verify LICENSE and NOTICE files exist and are placed correctly
   - [DONE] Check for Apache License headers in source files
   - [DONE] Basic RAT integration for license header validation

3. SBOM integration
   - [DONE] Generate a basic SBOM for release artifacts
   - Store SBOMs with release metadata
   - Add SBOM management options to UI
   - Ensure that release managers are made aware of SBOM quality and contents in the UI
   - Add ability to upload existing SBOMs
   - Add ability to validate uploaded SBOMs
   - [Export data through the Transparency Exchange API](https://github.com/apache/tooling-trusted-release/issues/8)

## Advanced RC validation

1. Reproducible build verification
   - [DONE] Accept upload of binary packages
   - Compare built artifacts with any existing provided binary artifacts
   - Give a detailed report of differences between user provided builds

2. Dependency analysis
   - Parse and validate dependency licenses
   - Check for prohibited licenses
   - Generate dependency reports
   - Flag dependency vulnerabilities

3. Distribution channel integration
   - Add PyPI distribution support
   - Implement Maven Central publishing
   - Add Docker Hub integration
   - Support test distribution channels

## Process automation

These are long term implementation requirements.

1. Vote management
   - Automate vote thread creation
   - Track votes and calculate results
   - Generate vote summaries
   - Handle binding vs non-binding votes
   - Display vote status and timeline

2. Release announcement
   - Template-based announcement generation with all required metadata
   - Support customisation by PMCs
   - Automate mailing list distribution

3. GitHub integration
   - Support GHA-based release uploads
   - Add release tagging integration
   - Support automated PR creation
   - Implement security checks for GHA workflows

## Success metrics

- Increased number of PMCs using the platform
- Reduction in release process duration
- Decreased number of failed release votes
- Improved compliance with ASF release policies
- Reduced manual intervention in release process
