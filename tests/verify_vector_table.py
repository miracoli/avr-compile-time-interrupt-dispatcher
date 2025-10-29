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


def load_vectors_section(
    binary_path: Path, start: int, end: int
) -> tuple[list[str], str]:
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

    relevant_lines: dict[int, str] = {}
    current_section = "<unknown>"
    table_section = ""

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Disassembly of section "):
            current_section = stripped[len("Disassembly of section ") :].rstrip(":")
            continue

        parsed = parse_jmp_line(line)
        if not parsed:
            continue

        address, _ = parsed
        if start <= address < end:
            relevant_lines[address] = line
            if not table_section:
                table_section = current_section

    if not relevant_lines:  # pragma: no cover - defensive
        headings = [line.strip() for line in lines if line.startswith("Disassembly of section ")]
        preview = "\n".join(lines[:40])
        message = [
            "Could not identify vector-table JMPs in avr-objdump output.",
            "Expected entries covering the address range "
            f"[{start:#06x}, {end:#06x}).",
        ]
        if headings:
            message.append("Found the following section headers:")
            message.extend(f"  {header}" for header in headings)
        else:
            message.append("No disassembly section headers were present in the output.")
        message.append("First 40 lines of avr-objdump output:")
        message.append(preview)
        raise RuntimeError("\n".join(message))

    ordered = [relevant_lines[address] for address in sorted(relevant_lines)]
    return ordered, table_section or "<unknown>"


_NM_VECTOR_RE = re.compile(r"^([0-9a-fA-F]+)\s+\w\s+(__vectors_(?:start|end))$")


def locate_vector_bounds(binary_path: Path) -> tuple[int, int]:
    result = subprocess.run(
        ["avr-nm", str(binary_path)],
        check=False,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError("avr-nm failed:\n" + (stderr or "(no stderr output)"))

    start = end = None
    for line in result.stdout.splitlines():
        match = _NM_VECTOR_RE.match(line.strip())
        if not match:
            continue
        address = int(match.group(1), 16)
        symbol = match.group(2)
        if symbol.endswith("start"):
            start = address
        else:
            end = address

    if start is None or end is None:
        raise RuntimeError(
            "Could not find __vectors_start/__vectors_end in avr-nm output."
        )

    if end <= start:
        raise RuntimeError(
            f"Vector table end {end:#06x} is not greater than start {start:#06x}."
        )

    if (end - start) % 4:
        raise RuntimeError(
            "Vector table size is not a multiple of 4 bytes: "
            f"start={start:#06x}, end={end:#06x}"
        )

    return start, end


_JMP_PREFIX_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+){2,}\s+jmp\b", re.IGNORECASE
)


def parse_jmp_line(line: str) -> tuple[int, str] | None:
    match = _JMP_PREFIX_RE.match(line)
    if not match:
        return None

    address = int(match.group(1), 16)
    symbols = re.findall(r"<([^>]+)>", line)
    symbol = symbols[-1] if symbols else ""
    return address, symbol


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

    start, end = locate_vector_bounds(args.binary)
    if start != 0:
        raise SystemExit(
            "Expected __vectors_start to resolve to address 0 but it was "
            f"{start:#06x}"
        )

    section_lines, section_name = load_vectors_section(args.binary, start, end)

    entries = []
    for line in section_lines:
        parsed = parse_jmp_line(line)
        if not parsed:
            continue
        address, symbol = parsed
        entries.append((address, symbol, line))

    if not entries:
        raise SystemExit("Did not find any jmp entries while parsing the vector table")

    if entries[0][0] != start:
        raise SystemExit(
            "Expected first vector entry at address 0, but found line:\n" + entries[0][2]
        )

    expected_entries = (end - start) // 4
    if len(entries) != expected_entries:
        raise SystemExit(
            "Vector table entry count mismatch: expected "
            f"{expected_entries} entries for range [{start:#06x}, {end:#06x}) "
            f"but found {len(entries)}"
        )

    for index, (address, symbol, line) in enumerate(entries):
        expected_address = start + index * 4
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
        raise SystemExit(str(err)) from err
