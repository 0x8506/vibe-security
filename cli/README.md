# vibe-security

Security scanner and fixer for AI coding assistants - find, verify and fix security vulnerabilities.

## Installation

```bash
npm install -g vibe-security
```

## Usage

```bash
# Security Scanning
vibesec scan                # Scan for vulnerabilities
vibesec verify              # Verify security posture

# Install security rules for AI assistants
vibesec init --ai claude      # Claude Code
vibesec init --ai cursor      # Cursor
vibesec init --ai windsurf    # Windsurf
vibesec init --ai antigravity # Antigravity
vibesec init --ai copilot     # GitHub Copilot
vibesec init --ai all         # All assistants

# Version Management
vibesec versions              # List available versions
vibesec update                # Update to latest version
vibesec init --version v1.0.0 # Install specific version
```

## Development

```bash
# Install dependencies
bun install

# Run locally
bun run src/index.ts --help

# Build
bun run build

# Link for local testing
bun link
```

## License

CC-BY-NC-4.0
