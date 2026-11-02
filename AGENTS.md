# Project workflow

- The owner requires remote-only development for this project.
- Use the connected GitHub tools to inspect and change repository files directly on GitHub.
- Do not clone or download this repository, its dependencies, scanner binaries, or project artifacts onto the owner's device.
- Do not execute project code, tests, scanners, containers, or installation commands on the owner's device.
- Run validation only on GitHub-hosted Actions runners. Deployment runs on Hugging Face through the existing main-branch workflow.
- Do not initiate live scans as part of verification. Use offline tests and mocked target/provider responses.

- Prefer modules and providers that work without API keys. Keep optional credentials optional and disclose keyless coverage limitations. Do not add required API-key setup to the full pipeline.
