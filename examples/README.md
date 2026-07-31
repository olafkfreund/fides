# Fides examples

Copy-pasteable "golden path" pipelines showing the full Fides flow — provenance,
evidence, change-gate, approved deploy, runtime snapshot — end to end.

- [`github-release/`](github-release/) — GitHub Actions (uses the `setup-fides` +
  `fides-gate` reusable actions).
- [`gitlab-release/`](gitlab-release/) — GitLab CI (`.gitlab-ci.yml`).

Each maps its steps to the controls in `fides control catalog`. These live under
`examples/` and do not run inside this repo — copy them into your own project.
