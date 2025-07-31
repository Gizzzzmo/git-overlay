# AGENTS.md - Development Guide for git-overlay

## Build/Test Commands
- **Build**: `nix develop --command cargo build`
- **Test**: `nix develop --command cargo test`
- **Run**: `nix develop --command cargo run -- <subcommand>`
- **Single test**: `nix develop --command cargo test <test_name>`
- **Check**: `nix develop --command cargo check`

## Environment
- Uses Nix flake for development environment with Rust toolchain
- Run `nix develop` to enter development shell or prefix commands with `nix develop --command`

## Code Style
- **Imports**: Group std imports first, then external crates, then local modules
- **Naming**: snake_case for functions/variables, PascalCase for types/enums
- **Error handling**: Use Result<T, GitOverlayError> pattern, implement From traits for error conversion
- **Types**: Prefer explicit types, use Option/Result over panics

## Architecture
- Main CLI in `src/main.rs` using clap for argument parsing
- Git operations wrapped in `GitOverlay` struct managing base and overlay repositories
- Pattern matching utilities in `src/glob_to_regex.rs` for gitignore-style patterns
- Cross-platform path handling with conditional compilation for Unix/non-Unix
