# Contributing

Thank you for helping improve `redirectcage`.

## Ground rules

- Keep the package free of runtime dependencies. Development-only test tooling
  must stay out of `dependencies`.
- Preserve strict fail-closed behavior for untrusted input.
- Keep `src/index.mjs` the single source of truth. Never edit `cjs/index.cjs`
  directly.
- Run `node scripts/build-cjs.mjs` after changing the source and include the
  generated CommonJS diff.
- Add deterministic tests for every behavior change. Include both safe and
  hostile inputs when the change affects validation.
- Keep support for Node 18, 20, 22 and 24 on Linux and Windows.
- Do not use em dash or en dash characters in repository files.
- Do not include local machine paths, private account data, tokens or real
  credentials in files, tests or commit messages.

## Development setup

No install step is required for the core suite. Run `npm ci` once before the fast-check fuzz suite.

```sh
node scripts/build-cjs.mjs
npm test
npm ci
npm run test:fuzz
npm pack --dry-run
```

The test command is:

```sh
node --test tests/*.test.mjs
```

CI first verifies that the generated CommonJS build is current and then runs
the same test command on Node 18, 20, 22 and 24 on Linux and Windows. For a
Windows `cmd.exe` local run on Node 18 or 20, use `npm run test:windows`.

## Security-sensitive changes

URL validation changes need a clear threat model in the pull request. State the
input, the parser being defended, the browser or downstream normalization that
makes it dangerous, and why the new canonical output is safe.

Do not relax these defaults without a strong reason and a separate CVE-quality
analysis:

- Protocol-relative targets are rejected.
- Backslashes are rejected literally and after decoding.
- Raw whitespace, control characters and invisible formatting characters are
  rejected.
- Dangerous and non-HTTP schemes are rejected.
- Absolute URLs require an explicit allowlist.
- Userinfo and IP literals require explicit opt-in.
- Malformed percent encoding is rejected.
- Unknown and prototype-polluting option keys are rejected.

## Pull requests

Keep changes focused. Describe the behavior before and after, list the exact
test count from the final local run, and say whether the change affects the
public API. Small documentation fixes are welcome and do not need review
theater, but inaccurate security claims are worse than missing documentation.
