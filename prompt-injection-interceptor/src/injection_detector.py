"""Prompt Injection Detector.

Scans content for prompt injection attacks using pattern matching,
structural analysis, and heuristic scoring.

This module is designed to run OUTSIDE the LLM's context, providing
deterministic detection that cannot be influenced by the content it examines.
"""

import re
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    """Result of scanning content for prompt injection."""

    is_safe: bool
    score: int
    detections: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Determine safety based on score threshold."""
        # Score of 50+ is considered unsafe
        if self.score >= 50:
            object.__setattr__(self, 'is_safe', False)


class InjectionDetector:
    """Detects prompt injection attempts in content.

    Uses multiple detection layers:
    1. Pattern matching - known injection phrases
    2. Structural analysis - hidden elements, encoding
    3. Heuristic scoring - accumulate risk scores
    """

    # Scoring thresholds
    BLOCK_THRESHOLD = 50
    REVIEW_THRESHOLD = 20

    # ==========================================================================
    # PATTERN DEFINITIONS
    # ==========================================================================

    # Known injection phrases with their scores
    INJECTION_PATTERNS: list[tuple[str, int, str]] = [
        # (pattern, score, description)

        # Direct instruction override attempts
        (r"IGNORE\s+(ALL\s+)?(PREVIOUS\s+|PRIOR\s+|ABOVE\s+)?(INSTRUCTIONS?|PROMPTS?)",
         50, "Instruction override attempt"),
        (r"DISREGARD\s+(ALL\s+)?(PREVIOUS\s+|PRIOR\s+)?(INSTRUCTIONS?|PROMPTS?)",
         50, "Instruction override attempt"),
        (r"FORGET\s+(ALL\s+|YOUR\s+)?(PREVIOUS\s+|PRIOR\s+)?(INSTRUCTIONS?|PROMPTS?)",
         50, "Instruction override attempt"),
        (r"OVERRIDE\s+(ALL\s+)?(PREVIOUS\s+|PRIOR\s+)?(INSTRUCTIONS?|PROMPTS?)",
         50, "Instruction override attempt"),

        # New instruction injection
        (r"NEW\s+INSTRUCTIONS?\s*:", 50, "New instruction injection"),
        (r"SYSTEM\s+PROMPT\s*:", 50, "System prompt injection"),
        (r"UPDATED?\s+INSTRUCTIONS?\s*:", 40, "Instruction update attempt"),
        (r"REVISED\s+INSTRUCTIONS?\s*:", 40, "Instruction revision attempt"),

        # Role/persona hijacking
        (r"YOU\s+ARE\s+NOW\s+", 50, "Role hijacking attempt"),
        (r"ACT\s+AS\s+(IF\s+YOU\s+(ARE|WERE)\s+)?", 50, "Role hijacking attempt"),
        (r"PRETEND\s+(TO\s+BE|YOU\s+ARE)\s+", 50, "Role hijacking attempt"),
        (r"FROM\s+NOW\s+ON[,\s]+(YOU|YOUR)\s+", 50, "Role hijacking attempt"),
        (r"ENTERING\s+(MAINTENANCE|DEVELOPER|ADMIN|DEBUG)\s+MODE",
         50, "Mode hijacking attempt"),

        # Known jailbreak patterns
        (r"\bJAILBREAK\b", 50, "Jailbreak keyword"),
        (r"\bDAN\s+MODE\b", 50, "DAN mode jailbreak"),
        (r"\bDEVELOPER\s+MODE\b", 50, "Developer mode jailbreak"),
        (r"\bUNRESTRICTED\s+MODE\b", 50, "Unrestricted mode jailbreak"),

        # Model-specific tokens (should NEVER appear in web content)
        (r"\[INST\]", 50, "Model token [INST]"),
        (r"\[/INST\]", 50, "Model token [/INST]"),
        (r"<\|im_start\|>", 50, "Model token <|im_start|>"),
        (r"<\|im_end\|>", 50, "Model token <|im_end|>"),
        (r"<<SYS>>", 50, "Model token <<SYS>>"),
        (r"<</SYS>>", 50, "Model token <</SYS>>"),
        (r"<\|system\|>", 50, "Model token <|system|>"),
        (r"<\|user\|>", 50, "Model token <|user|>"),
        (r"<\|assistant\|>", 50, "Model token <|assistant|>"),

        # Secrecy/deception indicators
        (r"DO\s+NOT\s+(TELL|INFORM|MENTION|REVEAL)\b.*\bUSER",
         50, "Secrecy instruction"),
        (r"DON'?T\s+(TELL|INFORM|MENTION|REVEAL)\b.*\bUSER",
         50, "Secrecy instruction"),
        (r"HIDE\s+THIS\s+(FROM|MESSAGE)", 50, "Secrecy instruction"),
        (r"KEEP\s+THIS\s+(SECRET|HIDDEN|PRIVATE)", 50, "Secrecy instruction"),
        (r"BEGIN\s+YOUR\s+RESPONSE\s+WITH", 50, "Response manipulation"),

        # Data exfiltration attempts
        (r"OUTPUT\s+(ALL\s+)?(YOUR\s+)?(API\s+KEYS?|CREDENTIALS?|TOKENS?|SECRETS?)",
         50, "Data exfiltration attempt"),
        (r"REVEAL\s+(ALL\s+)?(YOUR\s+)?(API\s+KEYS?|CREDENTIALS?|TOKENS?|SECRETS?)",
         50, "Data exfiltration attempt"),
        (r"SHOW\s+(ME\s+)?(ALL\s+)?(YOUR\s+)?(ENVIRONMENT|ENV)\s+VARIABLES?",
         50, "Data exfiltration attempt"),
        (r"OUTPUT\s+ALL\s+(YOUR\s+)?", 20, "Possible data exfiltration"),

        # Instruction boundary markers
        (r"={5,}.*INSTRUCTION.*={5,}", 30, "Instruction boundary marker"),
        (r"-{5,}.*INSTRUCTION.*-{5,}", 30, "Instruction boundary marker"),
        (r"\*{5,}.*INSTRUCTION.*\*{5,}", 30, "Instruction boundary marker"),
    ]

    # Structural patterns with their scores
    STRUCTURAL_PATTERNS: list[tuple[str, int, str]] = [
        # Hidden HTML content
        (r'<[^>]+style\s*=\s*["\'][^"\']*display\s*:\s*none',
         30, "Hidden HTML (display:none)"),
        (r'<[^>]+style\s*=\s*["\'][^"\']*font-size\s*:\s*0',
         30, "Hidden HTML (zero font)"),
        (r'<[^>]+style\s*=\s*["\'][^"\']*color\s*:\s*(white|#fff|transparent)',
         20, "Hidden HTML (invisible color)"),
        (r'<[^>]+\bhidden\b[^>]*>', 25, "Hidden HTML (hidden attribute)"),
        (r'<[^>]+aria-hidden\s*=\s*["\']true["\']', 20, "Hidden HTML (aria-hidden)"),

        # HTML comments with suspicious content
        (r'<!--[^>]*(instruction|ignore|system|prompt)[^>]*-->',
         25, "Suspicious HTML comment"),

        # Base64 blocks (potential encoded instructions)
        (r'[A-Za-z0-9+/]{100,}={0,2}', 15, "Large Base64 block"),

        # Invisible Unicode characters
        (r'[\u200B\u200C\u200D\uFEFF]', 25, "Zero-width Unicode characters"),
        (r'[\u202A-\u202E\u2066-\u2069]', 25, "Text direction override characters"),
    ]

    def __init__(self):
        """Initialize detector with compiled patterns."""
        # Pre-compile patterns for efficiency
        self._compiled_injection = [
            (re.compile(pattern, re.IGNORECASE | re.MULTILINE), score, desc)
            for pattern, score, desc in self.INJECTION_PATTERNS
        ]
        self._compiled_structural = [
            (re.compile(pattern, re.IGNORECASE | re.DOTALL), score, desc)
            for pattern, score, desc in self.STRUCTURAL_PATTERNS
        ]

    def scan(self, content: str) -> ScanResult:
        """Scan content for prompt injection attempts.

        Args:
            content: The text content to scan

        Returns:
            ScanResult with safety determination, score, and detections
        """
        if not content:
            return ScanResult(is_safe=True, score=0, detections=[])

        score = 0
        detections: list[str] = []

        # Check injection patterns
        for pattern, points, description in self._compiled_injection:
            if pattern.search(content):
                score += points
                detections.append(f"Pattern: {description} (+{points})")

        # Check structural patterns
        for pattern, points, description in self._compiled_structural:
            if pattern.search(content):
                score += points
                detections.append(f"Structure: {description} (+{points})")

        # Determine safety
        is_safe = score < self.BLOCK_THRESHOLD

        return ScanResult(
            is_safe=is_safe,
            score=score,
            detections=detections
        )

    def scan_with_context(
        self,
        content: str,
        url: str | None = None,
        tool_name: str | None = None
    ) -> ScanResult:
        """Scan content with additional context for logging.

        Args:
            content: The text content to scan
            url: Optional source URL
            tool_name: Optional tool that retrieved the content

        Returns:
            ScanResult with safety determination, score, and detections
        """
        # For now, context doesn't affect scoring
        # Could be extended to adjust thresholds based on source reputation
        return self.scan(content)
