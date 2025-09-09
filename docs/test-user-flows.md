# Test user flows

To test the ATR, here are some example command line and GitHub user flows.

## Command line

To install the `atr` command, use the [instructions in the client `README.md`](https://github.com/apache/tooling-releases-client/tree/main?tab=readme-ov-file#quick-start), or simply use `uv run atr` instead of `atr`.

[Create a PAT](https://release-test.apache.org/tokens) using the UI, then store the value in `atr` configuration.

```
atr set tokens.pat "$PAT_FROM_UI"
```

You can view the configuration file to check that the value is set. **This will write secret values to stdout.**

```
atr config file
```

The following commands constitute roughly an entire flow, which will be reflected in the UI. We are using `tooling-test-example` as the project name. Don't forget to [create this or another project](https://release-test.apache.org/project/add/tooling), or [use an existing project](https://release-test.apache.org/committees) as applicable. Use your ASF UID `@apache.org` instead of `example`.

```
atr release start tooling-test-example 0.1+demo

atr upload tooling-test-example 0.1+demo example.txt ../example.txt

atr check wait tooling-test-example 0.1+demo -i 25

atr check status tooling-test-example 0.1+demo

atr release info tooling-test-example 0.1+demo

atr vote start tooling-test-example 0.1+demo 00002 -m example@apache.org

atr vote resolve tooling-test-example 0.1+demo passed

atr distribution record tooling-test-example 0.1+demo NPM None react 18.2.0 False False

atr release info tooling-test-example 0.1+demo

atr announce tooling-test-example 0.1+demo 00003 -m example@apache.org -s Subject -b Body
```

When finished with an example flow, it is recommended that you delete the version.

```
atr dev delete tooling-test-example 0.1+demo
```

If there is ever a problem with a JWT verification, try refreshing your JWT.

```
atr jwt refresh | wc
```

## GitHub actions

We use [the `tooling-asf-example`](https://github.com/apache/tooling-asf-example) repository to check our GitHub actions.

First, [start a new release in the ATR web UI](https://release-test.apache.org/).

You can then use the [`build-and-rsync-to-atr.yaml`](https://github.com/apache/tooling-asf-example/actions/workflows/build-and-rsync-to-atr.yaml) workflow to build Python wheel files and upload them to the ATR.

Then, start a vote in the ATR web UI. This cannot be linked here because the URL will depend on which project and version you use.

Use the [`resolve-vote-on-atr.yaml`](https://github.com/apache/tooling-asf-example/actions/workflows/resolve-vote-on-atr.yaml) workflow to resolve the vote.

Use the [`record-distribution-on-atr.yaml`](https://github.com/apache/tooling-asf-example/actions/workflows/record-distribution-on-atr.yaml) workflow to record an external distribution. The external distribution _must exist_ on the distribution platform, because the ATR fetches real metadata.

Use the [`announce-release-on-atr.yaml`](https://github.com/apache/tooling-asf-example/actions/workflows/announce-release-on-atr.yaml) workflow to announce the release and copy the files into the download area.
