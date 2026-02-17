# Adversarial Parser Corpus

This directory holds deterministic adversarial binary inputs used by
`crates/ffs-ondisk/tests/adversarial_corpus.rs`.

Coverage intent:

- Truncated inputs (0-24 bytes).
- Repeated-byte payloads (`0x00`, `0xFF`, `0xAA`, `0x55`, `0x3C`) with varying lengths.
- Structured malformed seeds with ext4/btrfs magic bytes and malformed tails/headers.

The harness asserts:

1. At least 50 `.bin` samples are present.
2. Every sample is processed by ext4 and btrfs parser entry points without panics.
3. `ParseError` variants are all exercised.
