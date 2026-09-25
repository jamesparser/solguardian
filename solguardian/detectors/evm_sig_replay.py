"""EVM detector: signature verification gaps (replay, nonce, deadline, malleability).

Rules:
  SR-001 ecrecover on an unbound digest: no EIP-712 domain / chainid / contract address
  SR-002 no spend-once tracking: a signature can be replayed inside the same contract
  SR-003 deadline handling missing (or a deadline parameter that is never checked)
  SR-004 signature malleability not constrained (s / v range)

Skill: skills/signature-replay/SKILL.md
"""

from __future__ import annotations

import re
from typing import List

from ..core.detector import Detector, register
from ..core.finding import Severity
from ..core.source import SourceFile, detect_chain

SIG_PARAMS = re.compile(r"\buint8\s+v\b[^)]*\bbytes32\s+r\b[^)]*\bbytes32\s+s\b|\bbytes\s+(?:calldata|memory)\s+sig")
ECRECOVER = re.compile(r"\becrecover\s*\(")
EIP712 = re.compile(r"\bEIP712\b|0x1901|domainSeparator|\b_hash\b|\bmsgHash\b|getStructuredHash")
UNBOUND_HASH = re.compile(r"0x1900|keccak256\s*\(\s*abi\.encodePacked\s*\(\s*\"\\x19\\x00")
NONCE_TRACK = re.compile(r"\b(?:nonce|usedSig|usedSignature|_usedHash|isUsed|usedProofs|signatureUsed)\w*\b")
NONCE_WRITE = re.compile(
    r"\b(?:_?[A-Za-z]*nonce\w*|_?used\w*|_?isUsed\w*|_?consumed\w*|_?spent\w*|_?revealed\w*|"
    r"_?executed\w*|_?redeemed\w*|_?consumedGas|_?signatureUsed)\w*"
    r"\s*(?:\[[^\]]*\])?\s*(?:=\s*(?:true|[^;=])|\+\+)"
)
DEADLINE = re.compile(r"\bdeadline\b|\bexpires\b|\bvalidUntil\b", re.I)
DEADLINE_CHECK = re.compile(r"(block\.timestamp|block\.number)\s*(<=|<|>=|>)\s*\w*(deadline|expires|validUntil)|\w*(deadline|expires|validUntil)\s*(<=|<|>=|>)\s*(block\.timestamp|block\.number)")
MALLEABILITY = re.compile(r"s\s*>\s*secp256k1n|0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0|\bs\s*<=\s*|\blow\s*s\b|checkSignature|tryRecover")


@register
class EvmSignatureReplayDetector(Detector):
    id = "evm_sig_replay"
    label = "Signature / replay / nonce / deadline gaps"
    language = "solidity"
    skill = "signature-replay"
    cwe = "CWE-294"

    def detect(self, file: SourceFile) -> List[dict]:
        from ..core import solidity

        src = solidity.parse(file.rel, file.index)
        chain = detect_chain(file.rel, file.text)
        findings: List[dict] = []

        for fn in src.functions:
            if not fn.has_body:
                continue
            # Only callable entry points can be replayed against. A `private`/`internal`
            # helper, or a `view`/`pure` function, cannot move value: the caller that uses it
            # is the attack surface, and flagging the helper is a false positive.
            if fn.visibility in ("private", "internal"):
                continue
            if fn.mutability in ("view", "pure"):
                continue
            body = fn.body
            verified = ECRECOVER.search(body) or SIG_PARAMS.search(fn.params)
            if not verified:
                continue
            line = src.index.line_of(fn.body_start + (ECRECOVER.search(body).start() if ECRECOVER.search(body) else 0))

            # SR-001: digest is not bound to (verifier, chain)
            if not EIP712.search(body) and not UNBOUND_HASH.search(body):
                findings.append(
                    self.make(
                        file,
                        rule="SR-001",
                        title="Unbound signature digest in %s() (cross-chain / cross-contract replay)" % fn.name,
                        severity=Severity.HIGH,
                        confidence=0.8,
                        line=line,
                        function=fn.name,
                        contract=fn.contract,
                        chain=chain,
                        description=(
                            "%s() verifies a signature with raw `ecrecover` on a caller-supplied hash. The digest does "
                            "not commit to the verifying contract address or the chain id (no EIP-712 domain separator), "
                            "so one valid signature is valid everywhere the same bytecode is deployed - every fork, every "
                            "testnet-to-mainnet copy, and every sibling contract that shares the signer." % fn.name
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Capture a legitimate signed payload on chain A (or from any off-chain consumer of the signer).",
                            "Replay it verbatim against the same deployment on chain B / a sibling contract.",
                            "No forging is required: the signature is authentic, just in the wrong context.",
                        ],
                        patch=[
                            "Use OpenZeppelin EIP712 + `ECDSA.recover(typedDigest, v, r, s)` so the domain binds "
                            "`address(this)` and `block.chainid`.",
                            "If hand-rolled, hash `0x19 0x01 domainSeparator structHash` and cache the domain separator "
                            "including chainid so forks invalidate it.",
                        ],
                        checklist_needles=["domain", "chainid", "eip-712"],
                        tags=["signature", "replay"],
                    )
                )

            # SR-002: nothing marks the signature as spent
            if not NONCE_WRITE.search(body) and not NONCE_WRITE.search(src.index.masked):
                findings.append(
                    self.make(
                        file,
                        rule="SR-002",
                        title="No spend-once tracking: %s() can be replayed forever" % fn.name,
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        line=fn.line,
                        end_line=fn.body_line_range[1],
                        function=fn.name,
                        contract=fn.contract,
                        chain=chain,
                        description=(
                            "%s() pays out on a verified signature but no nonce, no mapping write and no "
                            "already-used check exists anywhere in the contract. The signer's single authorisation is "
                            "therefore an unlimited mint: the same (v, r, s) can be submitted in an unbounded number of "
                            "transactions by anyone who has seen it once - including from public mempool history."
                            % fn.name
                        ),
                        evidence=file.line_text(fn.line),
                        exploit=[
                            "Observe one legitimate use of %s() (mempool, front-end, an airdrop claim)." % fn.name,
                            "Call it again with the identical doc/v/r/s - the require() on the recovered address still passes.",
                            "Repeat until the contract is empty; gas is the only cost.",
                        ],
                        patch=[
                            "Track spend: `require(!used[hash]); used[hash] = true;` keyed on the full digest.",
                            "Or carry a per-signer monotonic nonce inside the signed payload and compare it to storage.",
                        ],
                        checklist_needles=["nonce", "replay", "spent"],
                        tags=["signature", "replay", "missing-nonce"],
                    )
                )

            # SR-003: deadline
            has_deadline_param = bool(DEADLINE.search(fn.params))
            checked = bool(DEADLINE_CHECK.search(body))
            if (has_deadline_param and not checked) or (not has_deadline_param and not checked):
                findings.append(
                    self.make(
                        file,
                        rule="SR-003",
                        title="No signature expiry in %s()%s"
                        % (fn.name, " (deadline parameter ignored)" if has_deadline_param else ""),
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        line=fn.line,
                        function=fn.name,
                        contract=fn.contract,
                        chain=chain,
                        description=(
                            "%s() accepts a signature with no deadline and no expiry check%s. A signer's intent is "
                            "usually time-bounded - rates, collateral ratios and allowances change - so a signature that "
                            "was reasonable on the day it was signed can be catastrophic months later, and a leaked "
                            "offline payload never expires."
                            % (fn.name, " (a deadline argument would be required, not just accepted)" if has_deadline_param else "")
                        ),
                        evidence=file.line_text(fn.line),
                        exploit=[
                            "Collect signed payloads when conditions are favourable.",
                            "Hold them until prices/limits move in your favour, then submit.",
                        ],
                        patch=[
                            "Put `uint256 deadline` in the signed payload and `require(block.timestamp <= deadline, \"expired\")`.",
                            "Keep the default TTL short (minutes to hours) and document it for signers.",
                        ],
                        checklist_needles=["deadline", "expiry"],
                        tags=["signature", "deadline"],
                    )
                )

            # SR-004: malleability
            if ECRECOVER.search(body) and not MALLEABILITY.search(body):
                findings.append(
                    self.make(
                        file,
                        rule="SR-004",
                        title="Raw ecrecover without malleability checks in %s()" % fn.name,
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        line=line,
                        function=fn.name,
                        contract=fn.contract,
                        chain=chain,
                        description=(
                            "%s() calls `ecrecover` directly. Secp256k1 signatures are malleable: (v, r, s) and "
                            "(v', r, n-s) both recover the same address. Without a high-s rejection, and without "
                            "restricting v to {27,28}, the same authorisation appears as two different hashes, which "
                            "breaks any de-duplication or replay map keyed on the payload."
                            % fn.name
                        ),
                        evidence=file.line_text(line),
                        exploit=[
                            "Take a used signature, flip s to n - s and adjust v.",
                            "If dedupe keys on the raw payload rather than the recovered digest, the second variant passes.",
                        ],
                        patch=[
                            "Use OpenZeppelin `ECDSA.tryRecover`/`recover` which enforces low-s and v in {27,28}.",
                            "Key replay maps on the eip-712 digest, not on the submitted bytes.",
                        ],
                        checklist_needles=["malleab", "ECDSA"],
                        tags=["signature", "malleability"],
                    )
                )
        return findings
