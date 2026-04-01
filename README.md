# SourceCoin-Legacy: Simple Python Crypto Wallet and API Toolkit
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License: Educational](https://img.shields.io/badge/license-educational-lightgrey)](#license-and-attribution)

SourceCoin-Legacy is a simple cryptocurrency implemented in Python. This README explains what the project offers, how to get started, how the code is organized, and how to extend it. It covers the core ideas behind a lightweight wallet, a tiny blockchain, and a minimal API to interact with the system. The goal is to provide a clear, approachable path for learners and developers who want to explore crypto concepts without heavy dependencies or complex infrastructure.

---

## Table of Contents

- [What is SourceCoin-Legacy?](#what-is-sourcecoin-legacy)
- [Why This Project Matters](#why-this-project-matters)
- [Core Components and Concepts](#core-components-and-concepts)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Quick Workflow](#quick-workflow)
- [Project Structure and Architecture](#project-structure-and-architecture)
- [Data Models and Persistence](#data-models-and-persistence)
- [API Reference](#api-reference)
  - [Endpoints](#endpoints)
  - [Example Payloads](#example-payloads)
- [Wallet Features and Security Basics](#wallet-features-and-security-basics)
- [Blockchain Logic and Consensus](#blockchain-logic-and-consensus)
- [Running Locally](#running-locally)
- [Testing and Examples](#testing-and-examples)
- [Extending the Codebase](#extending-the-codebase)
- [API Documentation Overview](#api-documentation-overview)
- [Development Workflow](#development-workflow)
- [Release Management](#release-management)
- [Roadmap and Future Ideas](#roadmap-and-future-ideas)
- [Contributing](#contributing)
- [How to Contribute to the README and Documentation](#how-to-contribute-to-the-readme-and-documentation)
- [Design Decisions and Tradeoffs](#design-decisions-and-tradeoffs)
- [Illustrative Usage Examples](#illustrative-usage-examples)
- [Accessibility and Compatibility Notes](#accessibility-and-compatibility-notes)
- [Security Considerations and Learning Opportunities](#security-considerations-and-learning-opportunities)
- [Further Learning Resources](#further-learning-resources)
- [License and Attribution](#license-and-attribution)

---

## What is SourceCoin-Legacy?

SourceCoin-Legacy is a compact, educational cryptocurrency project written in Python. It provides a simple wallet, a lightweight blockchain with a basic proof-of-work mechanism, and a small API layer you can use to create transactions, inspect the chain, and manage wallets. The project emphasizes clarity over complexity, making it a good starting point for learning about crypto concepts such as blocks, transactions, hashes, and consensus.

The idea behind SourceCoin-Legacy is to offer a practical, runnable demonstration that you can read, run, and extend. The code is designed to be readable and approachable. It is not meant to be a production-ready cryptocurrency. It is a learning tool, a playground for exploring how a crypto wallet and a blockchain can work together, and a stepping stone for building more advanced features.

---

## Why This Project Matters

- It demonstrates core concepts in a tangible way. You can see how a chain of blocks connects, how transactions are formed, and how a wallet can sign and verify messages.
- It gives you a practical sandbox to learn Python coding while tackling real-world ideas like cryptography, serialization, and network interfaces.
- It serves as a reference implementation for educational purposes. You can compare it with other open-source projects to understand design tradeoffs.
- It helps developers understand how a minimal API can expose essential actions without adding unnecessary complexity.

---

## Core Components and Concepts

- **Blockchain core**: A simple sequence of blocks. Each block contains an index, a timestamp, a list of transactions, a hash of the previous block, and a nonce. The chain is tamper-evident: altering a block would require recomputing hashes for subsequent blocks.
- **Transactions**: Transfers of SourceCoin from one wallet to another. A transaction includes the sender, recipient, amount, and a timestamp. Signatures provide authenticity and non-repudiation.
- **Wallets**: Public/private key pairs to identify users. Public keys serve as wallet addresses. Private keys sign transactions to prove ownership of funds.
- **Proof of work**: A lightweight consensus mechanism that requires a miner to discover a nonce that satisfies a simple difficulty condition. This helps deter bad actors, even in a learning environment.
- **API**: A small REST-like interface to fetch the blockchain, submit transactions, view wallet balances, and simulate mining. The API is intentionally compact to keep the focus on the underlying concepts.
- **Persistence**: The chain and wallet data are stored locally in JSON files. This keeps setup simple and makes it easy to inspect data structures.
- **CLI and examples**: A command-line interface helps you experiment with creating wallets, sending coins, querying the chain, and starting a local node.

---

## Getting Started

### Prerequisites

- Python 3.8 or newer
- `pip` available in your environment

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/zhaojun83/SourceCoin-Legacy/SourceCoin-Legacy.git
cd SourceCoin-Legacy
pip install -r requirements.txt
```

If you prefer to use a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

To obtain a packaged release instead, visit the [Releases page](https://github.com/zhaojun83/SourceCoin-Legacy/releases) and download the asset that matches your platform.

### Quick Workflow

1. Create a wallet and note your address.
2. Check your balance via the API or CLI.
3. Build a transaction to another wallet, sign it with your private key, and submit it.
4. Mine a block to include the pending transaction.
5. Inspect the chain to verify the result.

---

## Project Structure and Architecture

```
SourceCoin-Legacy/
├── src/
│   ├── blockchain/   # Block structure, hashing, and consensus logic
│   ├── wallet/       # Key generation, signing, and address handling
│   └── api/          # Lightweight REST-like API layer
├── tests/            # Unit and integration tests
├── examples/         # Demo scripts illustrating typical flows
├── docs/             # Design notes, data models, and API schemas
├── scripts/          # Convenience scripts for local development
└── requirements.txt  # Python dependencies
```

---

## Data Models and Persistence

- **Block**: Contains an index, timestamp, list of transactions, hash of the previous block, and a nonce produced by proof-of-work.
- **Transaction**: Records sender, recipient, amount, timestamp, and an optional digital signature. Signatures ensure only the wallet owner can authorize transfers.
- **Wallet**: Based on a public/private key pair. The public key is the address; the private key signs messages to prove ownership.
- **Chain persistence**: The blockchain and wallets are serialized to JSON files for easy inspection and restoration. JSON keeps data human-readable and easy to modify during experiments.

---

## API Reference

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/blocks` | Retrieve the current blockchain |
| `POST` | `/transactions` | Submit a new transaction |
| `GET` | `/wallets/{address}` | Fetch balance and wallet details |
| `POST` | `/mine` | Trigger mining to package pending transactions into a block |
| `GET` | `/status` | Return basic health and status information about the node |

### Example Payloads

Submit a transaction:

```json
{
  "sender": "0xABCD...",
  "recipient": "0x1234...",
  "amount": 10,
  "timestamp": 1712000000,
  "signature": "base64-encoded-signature"
}
```

Response from `GET /blocks`:

```json
[
  {
    "index": 0,
    "timestamp": 1711900000,
    "transactions": [],
    "previous_hash": "0",
    "nonce": 0,
    "hash": "0000abc..."
  }
]
```

---

## Wallet Features and Security Basics

- **Wallet creation**: Generate a private/public key pair. The public key serves as the wallet address. The private key must stay private; it signs transactions to prove ownership.
- **Signing**: Transactions are signed with the private key. The signature proves that the sender controlled the private key corresponding to the sender's address.
- **Balances**: Balances are determined by scanning the blockchain. Each transaction contributes to the available balance and unspent outputs are tracked locally.
- **Security basics**: Keep private keys on a secure device. Use a passphrase or encryption to protect keys at rest. If you lose a private key, you lose access to the funds associated with that wallet.

---

## Blockchain Logic and Consensus

- **Chain integrity**: Each block references the previous block by hash. This linkage makes the chain tamper-evident.
- **Proof of work**: The algorithm requires a nonce that satisfies a difficulty condition. Miners perform computations to discover a valid nonce and then broadcast the new block.
- **Consensus on a single chain**: In a simple environment, the longest valid chain is considered the authoritative chain. If two miners produce different blocks simultaneously, the network will converge on the longer chain as more blocks are added.
- **Handling forks**: Forks are natural in a distributed network. The implementation handles fork resolution by choosing the longest valid chain, ensuring eventual consistency after network stabilization.

---

## Running Locally

```bash
# Start the API server
python -m src.api

# Or run the CLI
python -m src.cli
```

Typical local workflow:

```bash
# Create a wallet
python -m src.cli wallet create

# Check balance
python -m src.cli wallet balance <address>

# Submit a transaction
python -m src.cli tx send --from <address> --to <recipient> --amount 5

# Mine a block
python -m src.cli mine
```

Use `curl` or any HTTP client to interact with the API directly:

```bash
curl http://localhost:5000/blocks
curl http://localhost:5000/status
```

---

## Testing and Examples

Run the test suite:

```bash
python -m pytest tests/
```

- **Tests**: Basic tests ensure core behavior such as transaction creation, signature verification, block hashing, and chain integrity. Tests help you confirm that modifications maintain expected behavior.
- **Examples**: The `examples/` directory contains short scripts that illustrate typical flows. Run any of them to see how wallet creation, transaction submission, and mining interact.
- **Documentation**: The `docs/` directory contains design notes, data models, and API schemas. Reading these documents helps you understand the decisions behind the implementation.

---

## Extending the Codebase

- **Adding new features**: You can add more transaction types, support multi-signature wallets, or implement a more advanced consensus algorithm. Start with small, testable changes to avoid destabilizing the core.
- **Improving security**: You can implement hardware wallet integration, secure key storage, and encryption at rest. Build a test suite that exercises security-critical paths.
- **Networking enhancements**: You can add peer-to-peer networking, message broadcasting, and synchronization across multiple local nodes. Start with a simple local mesh network model.
- **API expansion**: Extend the API with new endpoints for rate limiting, wallet import/export, or advanced search capabilities. Keep the API versioned to avoid breaking changes for users.

---

## API Documentation Overview

The API surface is intentionally small. It focuses on core actions required to interact with a minimal cryptocurrency: view the chain, create wallets, and submit transactions.

Endpoints are documented with example payloads and responses in the [API Reference](#api-reference) section above. JSON is the primary data interchange format.

Authentication considerations: the default API is not designed for public exposure. In learning setups, keep it local and use basic authentication or token-based access to limit exposure during experiments.

---

## Development Workflow

- **Cloning and branching**: Create a feature branch for each change. Keep commits focused and small. Write tests for new functionality.
- **Running tests**: Use the test suite to verify behavior after changes. Ensure the tests cover edge cases, such as handling invalid signatures or negative transfer amounts.
- **Documentation updates**: Update docs and in-line comments whenever you add or modify features. Clear documentation helps future contributors understand your changes.
- **Code reviews**: Submit pull requests with a clear description of the change, its motivation, and potential impacts. Include tests and usage examples when possible.

---

## Release Management

- **Versioning**: Use semantic versioning for releases (major.minor.patch). Each release notes the changes, the new features, and any bug fixes.
- **Asset packaging**: The [Releases page](https://github.com/zhaojun83/SourceCoin-Legacy/releases) hosts platform-specific assets. Each asset is tested for basic functionality on its target platform.
- **Changelog**: Keep a simple changelog that the community can read quickly. The changelog helps users see what changed and why it matters.
- **Security fixes**: If you discover vulnerabilities, patch quickly and publish a new release with a clear explanation of the fix and the affected areas.

---

## Roadmap and Future Ideas

- **Cross-platform wallets**: Extend support to more platforms and provide native binaries for Windows, macOS, and Linux.
- **Enhanced privacy**: Introduce optional privacy features using simple cryptographic techniques that still maintain transparency in the chain.
- **Richer API**: Add endpoints for batch transactions, address-to-address metadata, and transaction templates to facilitate automation.
- **Graphical user interface**: Build a minimal desktop UI that interacts with the API for users who prefer a GUI over a CLI.
- **Educational notebooks**: Create notebooks that walk through the codebase step-by-step, highlighting how data flows from wallet to blockchain to API.

---

## Contributing

- **How to contribute**: Fork the repository, create a feature branch, implement your idea, write tests, and submit a pull request. Follow the project's coding style and standards.
- **Getting help**: Open issues to report bugs or request features. Provide clear reproduction steps and any relevant environment details.
- **Acknowledgments**: This project draws on widely used cryptography concepts and learning resources. Credits go to educators and open-source contributors who help shape approachable crypto education.

---

## How to Contribute to the README and Documentation

- **Improve examples**: Add new, realistic example workflows that reflect how a user might employ the wallet in day-to-day tasks.
- **Expand API docs**: Flesh out endpoint schemas, typical request/response payloads, and error handling strategies.
- **Clarify data models**: Add more diagrams or pseudo-entity-relationship views to describe blocks, transactions, and wallets.
- **Provide cross-language references**: If you plan to explore porting the project to other languages, include starter guides and mapping tables.

---

## Design Decisions and Tradeoffs

- **Simplicity vs scale**: The project favors readability and clarity over performance. This makes it easier to learn and extend but means it is not optimized for production-scale throughput.
- **Deterministic behavior**: The design uses deterministic algorithms with clear inputs and outputs. This makes it straightforward to test and reason about.
- **Local persistence**: JSON-based persistence keeps data human-readable and easy to inspect. It also reduces setup friction for learners, though it is not suitable for high-security storage.
- **Security practicality**: The wallet and signing flow demonstrate cryptographic concepts without introducing heavy security layers. In a learning context, you can later replace the crypto primitives with stronger implementations.

---

## Illustrative Usage Examples

### Creating a wallet and checking balance

```bash
python -m src.cli wallet create
# Output: Address: 0xABCD...

python -m src.cli wallet balance 0xABCD...
# Output: Balance: 0 SRC
```

### Submitting a transaction

```bash
python -m src.cli tx send --from 0xABCD... --to 0x1234... --amount 10
# The CLI signs the transaction with your private key and submits it to the API
```

### Mining a block

```bash
python -m src.cli mine
# Pending transactions are packaged into a new block; balances update accordingly
```

### Inspecting the chain

```bash
curl http://localhost:5000/blocks
# Returns the full blockchain as JSON; verify previous_hash consistency across blocks
```

---

## Accessibility and Compatibility Notes

- **Platform coverage**: The release assets are prepared to run on common platforms, including Windows and Unix-like systems. Choose the asset that matches your OS to avoid setup friction.
- **Python version**: The code is written for Python 3.8+. If you encounter syntax or import issues, ensure your interpreter is up to date.
- **Dependencies**: The project relies on a small set of dependencies that are easy to install with `pip`. Using a virtual environment keeps dependencies isolated and clean.

---

## Security Considerations and Learning Opportunities

- **Signing and verification**: The wallet uses digital signatures to authenticate transactions. This is a good starting point to learn how signatures work in distributed systems.
- **Data integrity**: The blockchain ensures that altering a block would require recomputing hashes for subsequent blocks. This creates a chain of trust that is easy to analyze in a learning context.
- **Private key handling**: Treat private keys as highly sensitive data. In practice, store them in secure storage or a hardware wallet and avoid exposing them in code or logs.
- **Network exposure**: In learning environments, keep the API and nodes on a private network or localhost. This reduces exposure to the public internet while you experiment.

---

## Further Learning Resources

- **Python cryptography basics**: A gentle introduction to public-key cryptography, digital signatures, and basic hashing.
- **Blockchain fundamentals**: Reads about blocks, chains, consensus, and mining to build a stronger mental model.
- **API design for microservices**: Learn how to design small, robust interfaces that are easy to test and maintain.
- **Testing strategies**: Explore unit tests, integration tests, and property-based tests to improve code quality.

---

## License and Attribution

This project is provided for educational purposes to help learners understand how a simple cryptocurrency wallet and blockchain can work. It is not intended for production use.

Credit the authors and contributors by name in the repository. If you use or adapt the code, please maintain attribution and reference back to SourceCoin-Legacy.