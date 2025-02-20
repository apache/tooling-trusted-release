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

2. Enhance RC display
   - [DONE] Augment raw file hashes with the original filenames in the UI
   - [DONE] Add file size and upload timestamp
   - [DONE] Improve the layout of file listings
   - [DONE] Show KB, MB, or GB units for file sizes
   - [DONE] Add a standard artifact naming pattern based on the project and product
   - [DONE] Potentially add the option to upload package artifacts without signatures
   - Show validation status indicators
   - Add developer RC download buttons with clear verification instructions

3. Improve key management interface
   - [DONE] Display which PMCs are using each key
   - [DONE] Add key expiration warnings
   - Fix reported problem with adding keys
   - Add debugging output error messages for when key addition fails
   - Allow adding keys from a KEYS file

4. Release status dashboard
   - Add progress indicators for release phases
   - Show current blockers and required actions
   - Add quick actions for release managers

Advanced tasks, possibly deferred
   - Implement a key revocation workflow
   - Check RC file naming conventions
   - Add ability to sign artifact hashes on the platform using JS

## Task scheduler

We aim to work on the task scheduler in parallel with the UX improvements above. Artifact validation and the release status dashboard are dependent on tasks, which are managed by the task scheduler.

1. Task runner workers
   - Implement worker process with RLIMIT controls for CPU and RAM
   - Add disk usage tracking through API and psutil polling
   - Add rollback or reporting for failed tasks
   - Ensure idempotent operations where possible
   - Implement safe handling for compressed asset expansion
   - Test external tool use

2. Orchestrating scheduler and resource management
   - Implement process-based task isolation
   - Create task table in sqlite database
   - Add task queue management
   - Track and limit disk usage per task in the scheduler

Advanced tasks, possibly deferred
   - Check fair scheduling across cores
   - Add task monitoring and reporting

## Site improvements

1. Ensure that performance is optimal and debugging is easy
   - Add page load timing metrics to a log
   - Add a basic metrics dashboard
   - Ensure that all errors are caught and logged or displayed

2. Increase the linting and type checking
   - Potentially add blockbuster

## Basic RC validation

These tasks are dependent on the task scheduler above.

1. Basic artifact validation
   - Implement basic structure validation (archives, signatures)

2. License compliance
   - Verify LICENSE and NOTICE files exist and are placed correctly
   - Check for Apache License headers in source files
   - Basic RAT integration for license header validation

3. SBOM integration
   - Generate a basic SBOM for release artifacts
   - Store SBOMs with release metadata
   - Add SBOM management options to UI

## Advanced RC validation

1. Reproducible build verification
   - Accept upload of binary artifact builds
   - Compare built built artifacts with any existing provided binary artifacts
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
