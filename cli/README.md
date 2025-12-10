# vibe-security

Security scanner and fixer for AI coding assistants - find, verify and fix security vulnerabilities.

**Repository:** https://github.com/0x8506/vibe-security

## Installation

```bash
npm install -g vibe-security
npm install -g vibe-security@latest                 # Update to latest version
```

## Usage

```bash
# Install security rules for AI assistants
vibesec init --ai claude      # Claude Code
vibesec init --ai cursor      # Cursor
vibesec init --ai windsurf    # Windsurf
vibesec init --ai antigravity # Antigravity
vibesec init --ai copilot     # GitHub Copilot
vibesec init --ai all         # All assistants

# Version Management
vibesec versions              # List available versions
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

# Link for local
bun link
```

## License

CC-BY-NC-4.0
