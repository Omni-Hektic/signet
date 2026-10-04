# Part 3: Proxy Resolution & BscScan Integration

## Quick Start

```bash
# Set up environment
export BSCSCAN_API_KEY="your_key_here"  # Optional, uses public tier if unset

# Audit a BSC contract (with proxy resolution)
python3 solidity-auditor/tools/fetch_and_audit.py 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984 \
  --proxy \
  --cache-dir ./cache \
  --output findings.json

# View results
cat findings.json | jq '.findings[] | {checkId, severity, title}'
```

## Components

1. **proxy_resolver.py** — EIP-1967, EIP-1822, EIP-1167 proxy detection
2. **fetch_and_audit.py** — BscScan source fetcher + audit runner
3. **sig-11 Semgrep rules** — Uninitialized signer detection

## Documentation

- PROXY_RESOLVER.md — Proxy patterns and usage guide
- PART_3_IMPLEMENTATION.md — Full architecture and integration details

## Next Steps

- Part 4: Extended test harness (real BSC contracts)
- Part 5: Report schema & templates
- Part 6: Production deployment

