#!/usr/bin/env python3
"""
api/card.py: Customer-Facing Signet Risk Card Specification & Renderers

The Risk Card is the primary product surface for Signet.
It translates Slither SSA IR data-flow verdicts and Semgrep syntactic findings
into an instantly readable security verdict (< 3 seconds) for:
- Telegram trading bots & alert channels (Maestro, Trojan, Banana Gun)
- Terminal CLI for smart contract engineers & auditors
- Embeddable launchpad badges (PinkSale, Four.meme)
- High-throughput JSON payloads for programmatic callers
"""

import html
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

class FindingItem(BaseModel):
    check_id: str
    severity: str
    confidence: str
    title: str
    location: str
    action: str

class SignetRiskCard(BaseModel):
    token_address: str
    token_symbol: str = "UNKNOWN"
    token_name: str = "Unknown Token"
    chain_id: int = 56
    scan_timestamp: str = ""
    status: str = "VERIFIED_CLEAN"  # VERIFIED_CLEAN | CRITICAL_RISK | HIGH_RISK | MEDIUM_RISK | UNVERIFIED_SOURCE | IN_PROGRESS
    badge_text: str = "🟢 SIGNET VERIFIED [CLEAN]"
    source_verified: bool = True
    compiler_version: str = "Unknown"
    is_proxy: bool = False
    proxy_type: Optional[str] = None
    implementation_address: Optional[str] = None
    sig01_status: str = "PASS"  # PASS | FAIL | NA
    sig01_detail: str = "ecrecover zero-address check enforced or absent"
    sig03_status: str = "PASS"  # PASS | FAIL | NA
    sig03_detail: str = "Signature bound to chain ID 56"
    total_findings: int = 0
    findings: List[FindingItem] = Field(default_factory=list)
    recommendation: str = "SAFE: No cryptographic signature vulnerabilities identified."
    allow_trade: bool = True
    cached: bool = False
    latency_ms: float = 0.0

def card_from_audit_result(
    report: Dict[str, Any],
    cached: bool = False,
    latency_ms: float = 0.0
) -> SignetRiskCard:
    """Builds a SignetRiskCard from raw audit output."""
    token = report.get("token", {})
    metadata = report.get("auditMetadata", {})
    findings_raw = report.get("findings", [])
    
    address = token.get("address", "").lower()
    symbol = token.get("symbol") or "TOKEN"
    name = token.get("name") or token.get("implementationName") or "Contract"
    source_verified = bool(token.get("sourceVerified", True))
    
    proxy_info = token.get("proxy", {})
    is_proxy = bool(proxy_info.get("isProxy", False))
    proxy_type = proxy_info.get("type") if is_proxy else None
    implementation = proxy_info.get("implementation") if is_proxy else None
    
    compiler = metadata.get("detectorVersions", {}).get("solc", "Unknown")
    timestamp = metadata.get("scanTimestamp", "")

    # Parse findings
    parsed_findings: List[FindingItem] = []
    sig01_fail = False
    sig03_fail = False
    sig01_detail = "ecrecover zero-address check enforced or absent"
    sig03_detail = "Signature bound to chain ID 56"

    for f in findings_raw:
        check_id = f.get("checkId", "")
        sev = f.get("severity", "MEDIUM").upper()
        conf = f.get("confidence", "MEDIUM").upper()
        title = f.get("title", "")
        loc_dict = f.get("location", {})
        loc_str = f"{loc_dict.get('file', '')}:{loc_dict.get('line', '')}" if isinstance(loc_dict, dict) else str(loc_dict)
        act = f.get("action", "REVIEW_REQUIRED")
        
        parsed_findings.append(FindingItem(
            check_id=check_id,
            severity=sev,
            confidence=conf,
            title=title,
            location=loc_str,
            action=act
        ))

        if check_id == "SIG-01":
            sig01_fail = True
            sig01_detail = f"Unchecked ecrecover vulnerable to address(0) signature forgery ({sev})"
        elif check_id == "SIG-03":
            sig03_fail = True
            sig03_detail = f"Missing chain ID binding in permit hash ({sev})"

    # Determine status & badge
    if not source_verified:
        status = "UNVERIFIED_SOURCE"
        badge = "⚪ UNVERIFIED SOURCE [UNKNOWN RISK]"
        recommendation = "CAUTION: Unverified bytecode. Cryptographic delegation safety cannot be validated."
        allow_trade = False
    elif sig01_fail:
        status = "CRITICAL_RISK"
        badge = "🚨 CRITICAL RISK [SIGNATURE FORGERY]"
        recommendation = "DO NOT TRADE: Deployer or attacker can forge permit approvals to drain tokens."
        allow_trade = False
    elif sig03_fail:
        status = "MEDIUM_RISK"
        badge = "⚠️ HIGH RISK [CROSS-CHAIN REPLAY]"
        recommendation = "REPLAY RISK: Permits can be replayed across chains due to missing chain-id binding."
        allow_trade = False
    else:
        status = "VERIFIED_CLEAN"
        badge = "🟢 SIGNET VERIFIED [CLEAN]"
        recommendation = "SAFE: Zero signature delegation vulnerabilities detected."
        allow_trade = True

    return SignetRiskCard(
        token_address=address,
        token_symbol=symbol,
        token_name=name,
        chain_id=metadata.get("chainId", 56),
        scan_timestamp=timestamp,
        status=status,
        badge_text=badge,
        source_verified=source_verified,
        compiler_version=compiler,
        is_proxy=is_proxy,
        proxy_type=proxy_type,
        implementation_address=implementation,
        sig01_status="FAIL" if sig01_fail else "PASS",
        sig01_detail=sig01_detail,
        sig03_status="FAIL" if sig03_fail else "PASS",
        sig03_detail=sig03_detail,
        total_findings=len(parsed_findings),
        findings=parsed_findings,
        recommendation=recommendation,
        allow_trade=allow_trade,
        cached=cached,
        latency_ms=latency_ms
    )


# ---------------------------------------------------------------------------
# Telegram Card Renderer (Optimized for 3-Second Readability)
# ---------------------------------------------------------------------------
def render_telegram_card(card: SignetRiskCard) -> str:
    """
    Renders card in Telegram-compatible Markdown.
    Designed for instant comprehension by degens and trading bot channels.
    """
    trunc_addr = f"{card.token_address[:6]}...{card.token_address[-4:]}" if len(card.token_address) >= 10 else card.token_address
    
    lines = [
        "🛡️ *SIGNET RISK CARD* \\| *BSC Mainnet*",
        "━" * 28,
        f"*Token:* `${card.token_symbol}` \\(`{trunc_addr}`\\)",
        f"*Status:* {card.badge_text}",
        "",
        "*DE\\-ALIASING & PROXY INTEL:*"
    ]
    
    if card.is_proxy:
        impl_trunc = f"{card.implementation_address[:6]}...{card.implementation_address[-4:]}" if card.implementation_address else "Unknown"
        lines.append(f"• *Proxy:* Yes \\({card.proxy_type or 'Clone'}\\)")
        lines.append(f"• *Target Impl:* `{impl_trunc}`")
    else:
        lines.append("• *Proxy:* No \\(Direct Bytecode\\)")
        
    lines.append(f"• *Verified Source:* {'Yes' if card.source_verified else 'No ⚠️'}")
    lines.append("")
    lines.append("*CRYPTOGRAPHIC VERDICT:*")
    
    if card.sig01_status == "PASS":
        lines.append("✅ *SIG\\-01 (Zero\\-Address Forgery):* PASS")
    else:
        lines.append("❌ *SIG\\-01 (Zero\\-Address Forgery):* CRITICAL FAIL")
        
    if card.sig03_status == "PASS":
        lines.append("✅ *SIG\\-03 (Chain\\-ID Replay Binding):* PASS")
    else:
        lines.append("⚠️ *SIG\\-03 (Chain\\-ID Replay Binding):* VULNERABLE")
        
    lines.append("")
    lines.append(f"*ACTION:* {card.recommendation}")
    lines.append("━" * 28)
    
    perf = f"Cache HIT \\({card.latency_ms:.1f}ms\\)" if card.cached else f"Cold Scan \\({card.latency_ms:.1f}ms\\)"
    lines.append(f"⚡ _{perf}_ \\| Powered by *Signet*")
    
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Terminal CLI Card Renderer (ANSI Colors & UTF-8 Box Drawing)
# ---------------------------------------------------------------------------
def render_terminal_card(card: SignetRiskCard, use_color: bool = True) -> str:
    """Renders card in terminal CLI format with crisp borders."""
    C_GREEN = "\033[92m" if use_color else ""
    C_RED = "\033[91m" if use_color else ""
    C_YELLOW = "\033[93m" if use_color else ""
    C_CYAN = "\033[96m" if use_color else ""
    C_BOLD = "\033[1m" if use_color else ""
    C_RESET = "\033[0m" if use_color else ""

    status_color = C_GREEN if card.status == "VERIFIED_CLEAN" else (C_RED if "CRITICAL" in card.status else C_YELLOW)
    
    width = 64
    div = "─" * width

    lines = [
        f"┌{div}┐",
        f"│ {C_BOLD}{C_CYAN}🛡️  SIGNET RISK ASSESSMENT | BSC Mainnet (Chain ID 56){C_RESET}{' ' * (width - 50)}│",
        f"├{div}┤",
        f"│ Token:       {C_BOLD}${card.token_symbol}{C_RESET} ({card.token_name}){' ' * max(0, width - 20 - len(card.token_symbol) - len(card.token_name))}│",
        f"│ Address:     {card.token_address}{' ' * max(0, width - 15 - len(card.token_address))}│",
        f"│ Status:      {status_color}{C_BOLD}{card.badge_text}{C_RESET}{' ' * max(0, width - 15 - len(card.badge_text))}│",
        f"├{div}┤",
        f"│ {C_BOLD}DE-ALIASING & PROXY INTEL:{C_RESET}{' ' * (width - 27)}│",
        f"│   Proxy:          {'YES - ' + str(card.proxy_type) if card.is_proxy else 'NO (Direct Contract)'}{' ' * max(0, width - 21 - len(str(card.proxy_type) if card.is_proxy else 'NO (Direct Contract)'))}│",
    ]

    if card.is_proxy and card.implementation_address:
        lines.append(f"│   Implementation: {card.implementation_address}{' ' * max(0, width - 21 - len(card.implementation_address))}│")

    lines.extend([
        f"│   Source Code:    {'VERIFIED' if card.source_verified else 'UNVERIFIED / CLOSED'}{' ' * max(0, width - 21 - (8 if card.source_verified else 19))}│",
        f"├{div}┤",
        f"│ {C_BOLD}CRYPTOGRAPHIC FINDINGS:{C_RESET}{' ' * (width - 24)}│",
        f"│   [SIG-01] ecrecover zero-check:   {C_GREEN + 'PASS' if card.sig01_status == 'PASS' else C_RED + 'CRITICAL FAIL'}{C_RESET}{' ' * (width - 43 if card.sig01_status == 'PASS' else width - 52)}│",
        f"│   [SIG-03] Chain-ID replay check:  {C_GREEN + 'PASS' if card.sig03_status == 'PASS' else C_YELLOW + 'VULNERABLE'}{C_RESET}{' ' * (width - 43 if card.sig03_status == 'PASS' else width - 49)}│",
        f"├{div}┤",
        f"│ {C_BOLD}RECOMMENDATION:{C_RESET}{' ' * (width - 16)}│",
        f"│   {card.recommendation[:width-4]}{' ' * max(0, width - 4 - len(card.recommendation[:width-4]))}│",
        f"├{div}┤",
        f"│ Latency: {'Cache HIT' if card.cached else 'Cold Scan'} ({card.latency_ms:.1f}ms) | Signet Security Engine v1.0{' ' * max(0, width - 56 - len(f'{card.latency_ms:.1f}'))}│",
        f"└{div}┘"
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SVG Badge Renderer (Embeddable for Launchpads PinkSale / Four.meme)
# ---------------------------------------------------------------------------
def render_svg_badge(card: SignetRiskCard) -> str:
    """Generates an embeddable SVG badge matching Shields.io style."""
    if card.status == "VERIFIED_CLEAN":
        status_label = "verified clean"
        bg_color = "#28a745"
    elif card.status == "UNVERIFIED_SOURCE":
        status_label = "unverified"
        bg_color = "#6c757d"
    elif card.status == "PILOT_EXPIRED":
        status_label = "pilot expired"
        bg_color = "#495057"
    elif card.status == "CRITICAL_RISK":
        status_label = "forgery risk"
        bg_color = "#dc3545"
    elif card.status == "HIGH_RISK":
        status_label = "replay risk"
        bg_color = "#fd7e14"
    elif card.status == "IN_PROGRESS":
        status_label = "unverified"
        bg_color = "#6c757d"
    else:
        status_label = "unverified"
        bg_color = "#6c757d"

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="180" height="28" role="img" aria-label="signet: {status_label}">
  <title>signet: {status_label}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="180" height="28" rx="4" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="65" height="28" fill="#1b1e23"/>
    <rect x="65" width="115" height="28" fill="{bg_color}"/>
    <rect width="180" height="28" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="32" y="18" fill="#010101" fill-opacity=".3">SIGNET</text>
    <text x="32" y="17">SIGNET</text>
    <text x="122" y="18" fill="#010101" fill-opacity=".3">{status_label.upper()}</text>
    <text x="122" y="17">{status_label.upper()}</text>
  </g>
</svg>"""


# ---------------------------------------------------------------------------
# Trading Bot Direct Payload Renderer
# ---------------------------------------------------------------------------
def render_trading_bot_payload(card: SignetRiskCard) -> Dict[str, Any]:
    """
    Sub-millisecond decision payload for Maestro / Trojan / Banana Gun.
    Evaluates instant binary allow_trade status and proxy risk.
    """
    return {
        "address": card.token_address,
        "symbol": card.token_symbol,
        "allow_trade": card.allow_trade,
        "risk_level": "LOW" if card.status == "VERIFIED_CLEAN" else ("CRITICAL" if card.status == "CRITICAL_RISK" else "HIGH"),
        "is_proxy": card.is_proxy,
        "proxy_implementation": card.implementation_address,
        "source_verified": card.source_verified,
        "sig01_vulnerable": card.sig01_status != "PASS",
        "sig03_vulnerable": card.sig03_status != "PASS",
        "cached": card.cached,
        "latency_ms": card.latency_ms
    }
