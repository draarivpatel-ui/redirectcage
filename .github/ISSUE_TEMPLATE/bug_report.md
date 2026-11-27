---
name: Bug report
about: Report incorrect validation, canonicalization or packaging behavior
title: ''
labels: bug
assignees: ''
---

## Summary

Describe the incorrect behavior in one or two sentences.

## Minimal reproduction

```js
import { parseRedirectLocation } from 'redirectcage';

console.log(parseRedirectLocation('INPUT_HERE', {
  // options here
}));
```

## Input and options

- Input string:
- Complete options object:
- Node.js version:
- redirectcage version:
- Operating system:
- ESM, CommonJS, or both:

## Expected result

State the exact safe normalized output or error code you expected.

## Actual result

State the exact output, error code, or exception you observed.

## Security impact

Does this produce a browser-unsafe `Location` target? If yes, do not include a
working exploit beyond the minimal input needed to reproduce it. Consider using
a private security advisory instead.
