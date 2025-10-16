#!/usr/bin/env python3
"""Check that the generated .vectors table points at the expected symbols."""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binary",
        type=Path,
        help=(
            "Path to the AVR ELF or object file that contains the interrupt vector table."
        ),
    )
    return parser.parse_args()


def load_vectors_section(binary_path: Path) -> list[str]:
    result = subprocess.run(
        ["avr-objdump", "-D", str(binary_path)],
        check=False,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(
            "avr-objdump failed:\n" + (stderr or "(no stderr output)")
        )

    lines = result.stdout.splitlines()
    start_index = None
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("Disassembly of section .vectors"):
            start_index = idx + 1
            break
    if start_index is None:  # pragma: no cover - defensive
        headings = [line.strip() for line in lines if line.startswith("Disassembly of section ")]
        preview = "\n".join(lines[:40])
        message = ["Could not find .vectors section in avr-objdump output."]
        if headings:
            message.append("Found the following section headers:")
            message.extend(f"  {header}" for header in headings)
        else:
            message.append("No disassembly section headers were present in the output.")
        message.append("First 40 lines of avr-objdump output:")
        message.append(preview)
        raise RuntimeError("\n".join(message))

    section_lines: list[str] = []
    for line in lines[start_index:]:
        if line.startswith("Disassembly of section "):
            break
        section_lines.append(line)

    # Strip trailing empty lines that objdump sometimes leaves around.
    while section_lines and not section_lines[-1].strip():
        section_lines.pop()

    return section_lines


_JMP_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+){2,}\s+jmp\s+(?:0x)?[0-9a-fA-F]+\s+<([^>]+)>"
)


def classify_symbol(symbol: str) -> str:
    if symbol.startswith("reset"):
        return "reset"
    if "DummyHandler" in symbol and "__vector" in symbol:
        return "dummy"
    if "__vector_default" in symbol:
        return "default"
    return "other"


def main() -> int:
    args = parse_args()
    if not args.binary.exists():
        raise SystemExit(f"Input file '{args.binary}' does not exist")

    section_lines = load_vectors_section(args.binary)

    non_empty = next((line for line in section_lines if line.strip()), "")
    if not non_empty.startswith("00000000 "):
        raise SystemExit(
            "Expected .vectors to start at address 0, but first line was:\n" + non_empty
        )

    entries = []
    for line in section_lines:
        match = _JMP_RE.search(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        symbol = match.group(2)
        entries.append((address, symbol, line))

    if not entries:
        raise SystemExit("Did not find any jmp entries in the .vectors section")

    for index, (address, symbol, line) in enumerate(entries):
        expected_address = index * 4
        if address != expected_address:
            raise SystemExit(
                f"Vector {index} should be at byte offset {expected_address:#x} but line was:\n{line}"
            )

        classification = classify_symbol(symbol)
        if index == 0:
            if classification != "reset":
                raise SystemExit(
                    f"Vector 0 should jump to reset but instead targets '{symbol}'"
                )
        elif index == 1:
            if classification != "dummy":
                raise SystemExit(
                    "Vector 1 should jump to DummyHandler::__vector but line was:\n" + line
                )
        else:
            if classification != "default":
                raise SystemExit(
                    f"Vector {index} should jump to __vector_default but line was:\n" + line
                )

    print(
        f"Validated {len(entries)} interrupt vectors: reset, DummyHandler, and {len(entries) - 2} defaults."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as err:
        raise SystemExit(str(err))
