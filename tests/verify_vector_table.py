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


def load_vectors_section(binary_path: Path) -> tuple[list[str], str]:
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

    section_lines: list[str] = []
    current_section = "<unknown>"
    table_section = ""
    collecting = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Disassembly of section "):
            current_section = stripped[len("Disassembly of section ") :].rstrip(":")
            continue

        match = _JMP_RE.search(line)
        if not match:
            if collecting and stripped.startswith("0"):
                # Labels such as "00000000 <symbol>:" should not terminate the table.
                continue
            if collecting and stripped:
                # Encountered the first non-empty, non-JMP line after collecting entries.
                break
            continue

        address = int(match.group(1), 16)
        expected_address = len(section_lines) * 4

        if not collecting:
            if address != 0:
                # Ignore JMPs that are not part of the vector table prefix.
                continue
            collecting = True
            table_section = current_section
        elif address != expected_address:
            # We've reached a different block of JMP instructions; stop collecting.
            break

        section_lines.append(line)

    if not section_lines:  # pragma: no cover - defensive
        headings = [line.strip() for line in lines if line.startswith("Disassembly of section ")]
        preview = "\n".join(lines[:40])
        message = [
            "Could not identify a vector-table block in avr-objdump output.",
            "Looked for a dedicated .vectors section and, failing that, for the",
            "first sequence of JMP instructions starting at address 0.",
        ]
        if headings:
            message.append("Found the following section headers:")
            message.extend(f"  {header}" for header in headings)
        else:
            message.append("No disassembly section headers were present in the output.")
        message.append("First 40 lines of avr-objdump output:")
        message.append(preview)
        raise RuntimeError("\n".join(message))

    return section_lines, table_section or "<unknown>"


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

    section_lines, section_name = load_vectors_section(args.binary)

    entries = []
    for line in section_lines:
        match = _JMP_RE.search(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        symbol = match.group(2)
        entries.append((address, symbol, line))

    if not entries:
        raise SystemExit("Did not find any jmp entries while parsing the vector table")

    if entries[0][0] != 0:
        raise SystemExit(
            "Expected first vector entry at address 0, but found line:\n" + entries[0][2]
        )

    if len(entries) < 3:
        raise SystemExit(
            "Vector table appears truncated; expected at least 3 entries but "
            f"found {len(entries)}"
        )

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

    if section_name != ".vectors":
        print(
            "Note: .vectors section not present in disassembly; using sequential JMPs "
            f"from '{section_name}' as the vector table."
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
