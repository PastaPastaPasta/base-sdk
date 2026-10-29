# fork-ci

This branch holds the CI of pasta's fork of dashpay/base-sdk and nothing else. It has no history in
common with `develop` and is never merged into a branch bound for dashpay/base-sdk.

It is the fork's default branch because GitHub reads `workflow_dispatch` workflows only from the
default branch. `develop` still mirrors upstream, and every pull request still targets dashpay's
`develop`.

`.github/workflows/fork-ci.yml` runs the local comb (`contrib/git_filter.py base tip -- just test
lint fuzz::test`) with one job per commit. To run it:

```sh
gh workflow run fork-ci.yml -R PastaPastaPasta/base-sdk --ref fork-ci \
  -f label=<branch> -f base=<full sha> -f tip=<full sha>
```

Add `-f skip_commit_lint=true` only for `node-sdk-integration`, whose commits carry agent trailers that
`lint_commit` blocks. It skips that one linter; branches bound for dashpay/base-sdk never set it.
