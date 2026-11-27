# Good first issues

These starter ideas are deliberately bounded. Each can be completed without
changing the package's zero-dependency or fail-closed design.

## 1. Add a framework integration example

Add a small README example for one additional framework that exposes a
Node-compatible response object. Do not add a dependency. Explain which response
methods the example relies on.

## 2. Expand the OWASP vector corpus

Add individual deterministic tests for additional public CWE-601 bypass strings.
Each new vector needs the exact error code or safe canonical output and a short
reason it belongs in the corpus.

## 3. Improve error code documentation

Add a README table that groups every public `ERR_REDIRECTCAGE_*` code by caller
action. Keep the descriptions short and verify each code against `types/index.d.ts`.

## 4. Add a TypeScript consumer smoke fixture

Create a small type-only fixture that imports every public function and option
type. It must not add TypeScript or any other devDependency. CI can inspect it
as a source fixture rather than compiling it.

## 5. Write a migration note for permissive redirect code

Document how to migrate a common pattern such as `res.redirect(req.query.next)`
to `res.safeRedirect(req.query.next)`. Include the behavior change when input is
invalid.

## 6. Add nested callback guidance

Write a documentation section showing how to validate a `next` parameter again
when the first validated target is only an application route. Make clear that
the library does not recursively trust nested parameters.

## 7. Add a performance smoke benchmark

Add a local, non-CI benchmark script that measures typical safe and unsafe input
validation times without external packages. Keep it out of the published tarball
and document that results are machine-dependent.

## 8. Review canonicalization examples

Audit the README examples against actual output from `parseRedirectLocation`.
Fix any mismatch and add a test if an example was wrong.

## 9. Improve issue templates

Make the bug report template easier for non-experts to complete while preserving
the exact input, options, expected result and actual result fields.

## 10. Add a release checklist

Write a maintainer checklist covering generated CommonJS freshness, test count,
pack dry-run contents, documentation accuracy and security note review. Do not
automate publishing.
