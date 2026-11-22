# Contributing

- Run `cargo test --locked` and `cargo test --locked --all-features` before a pull request.
- Keep the zero-dependency core zero-dependency: new third-party crates go behind the `native`
  feature or another off-by-default feature, with the reason in the PR.
- A bug fix comes with a test that fails without it.
- Do not commit keys, tokens or real addresses; use documentation addresses (192.0.2.0/24).
