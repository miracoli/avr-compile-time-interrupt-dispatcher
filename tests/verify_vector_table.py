#!/usr/bin/env python3
"""Check that the generated .vectors table points at the expected symbols."""
from __future__ import annotations

import argparse
import re
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path


def parse_args() -> argparse.Namespace:
    """Parse command-line options for verifying the interrupt vector table."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binary",
        type=Path,
        help=(
            "Path to the AVR ELF or object file that contains the interrupt vector table."
        ),
    )
    parser.add_argument(
        "--expected-mnemonic",
        choices=("jmp", "rjmp", "any"),
        default="any",
        help=(
            "Require every vector-table entry to use the provided jump mnemonic. "
            "Set to 'any' (the default) to accept either absolute or relative jumps."
        ),
    )
    return parser.parse_args()


DISASSEMBLY_PREFIX = "Disassembly of section "


def load_vectors_section(
    binary_path: Path, start: int, end: int
) -> tuple[list[str], str]:
    """Load the disassembly lines that contain the interrupt vector table.

    Parameters:
        binary_path: Path to the AVR ELF/object file.
        start: Start address of the vector table.
        end: End address (exclusive) of the vector table.

    Returns:
        A tuple ``(lines, section_name)`` where ``lines`` is an ordered list of
        disassembly lines for the table and ``section_name`` identifies the
        section they originated from.
    """
    lines = _run_objdump(binary_path)
    relevant_lines, table_section = _collect_vector_lines(lines, start, end)

    if not relevant_lines:  # pragma: no cover - defensive
        raise RuntimeError(
            _format_missing_vectors_error(lines, start, end)
        )

    ordered = [relevant_lines[address] for address in sorted(relevant_lines)]
    return ordered, table_section or "<unknown>"


def _run_objdump(binary_path: Path) -> list[str]:
    """Execute ``avr-objdump`` and return its stdout split into lines.

    Parameters:
        binary_path: Path to the binary to disassemble.

    Returns:
        A list of output lines produced by ``avr-objdump``.

    Raises:
        RuntimeError: If ``avr-objdump`` exits with a non-zero status.
    """
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

    return result.stdout.splitlines()


def _collect_vector_lines(
    lines: list[str], start: int, end: int
) -> tuple[dict[int, str], str]:
    """Collect vector-table disassembly lines within the provided address range.

    Parameters:
        lines: Complete list of ``avr-objdump`` output lines.
        start: Start address of the vector table.
        end: End address (exclusive) of the vector table.

    Returns:
        A mapping of addresses to disassembly lines and the name of the section
        containing the first match.
    """
    relevant_lines: dict[int, str] = {}
    current_section = "<unknown>"
    table_section = ""

    for line in lines:
        section = _extract_section_name(line)
        if section is not None:
            current_section = section
            continue

        parsed = parse_jmp_line(line)
        if not parsed:
            continue

        address, _, _ = parsed
        if not (start <= address < end):
            continue

        if table_section and current_section != table_section:
            # Ignore lookalike JMP/RJMP instructions that live in other sections
            # (e.g. DWARF debug info).  The first matching section should be the
            # actual vector table, so once we have locked on to it we drop any
            # further matches from other sections that just happen to reuse the
            # same addresses.
            continue

        relevant_lines[address] = line
        if not table_section:
            table_section = current_section

    return relevant_lines, table_section


def _extract_section_name(line: str) -> str | None:
    """Extract the disassembly section name from an ``avr-objdump`` line."""
    stripped = line.strip()
    if stripped.startswith(DISASSEMBLY_PREFIX):
        return stripped[len(DISASSEMBLY_PREFIX) :].rstrip(":")
    return None


def _format_missing_vectors_error(
    lines: list[str], start: int, end: int
) -> str:  # pragma: no cover - defensive
    """Format an error message describing why vector-table lines were not found."""
    headings = [line.strip() for line in lines if line.startswith(DISASSEMBLY_PREFIX)]
    preview = "\n".join(lines[:40])
    message = [
        "Could not identify vector-table JMPs in avr-objdump output.",
        "Expected entries covering the address range ",
        f"[{start:#06x}, {end:#06x}).",
    ]
    if headings:
        message.append("Found the following section headers:")
        message.extend(f"  {header}" for header in headings)
    else:
        message.append("No disassembly section headers were present in the output.")
    message.append("First 40 lines of avr-objdump output:")
    message.append(preview)
    return "\n".join(message)



_NM_VECTOR_RE = re.compile(r"^([0-9a-fA-F]+)\s+\w\s+(__vectors_(?:start|end))$")


def locate_vector_bounds(binary_path: Path) -> tuple[int, int]:
    """Locate ``__vectors_start`` and ``__vectors_end`` using ``avr-nm``.

    Parameters:
        binary_path: Path to the AVR ELF/object file.

    Returns:
        A tuple ``(start, end)`` describing the address range of the vector
        table.

    Raises:
        RuntimeError: If ``avr-nm`` fails or the expected symbols are missing or
        inconsistent.
    """
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

    span = end - start
    if span % 2:
        raise RuntimeError(
            "Vector table size is not a multiple of 2 bytes: "
            f"start={start:#06x}, end={end:#06x}"
        )

    return start, end


_JMP_PREFIX_RE = re.compile(
    r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+){2,}\s+(r?jmp)\b",
    re.IGNORECASE,
)


def parse_jmp_line(line: str) -> tuple[int, str, str] | None:
    """Parse a disassembly line containing a JMP/RJMP instruction.

    Parameters:
        line: Line of disassembly text.

    Returns:
        ``None`` if the line is not a JMP/RJMP; otherwise a tuple of
        ``(address, symbol, mnemonic)`` extracted from the line.
    """
    match = _JMP_PREFIX_RE.match(line)
    if not match:
        return None

    address = int(match.group(1), 16)
    mnemonic = match.group(2).lower()
    symbols = re.findall(r"<([^>]+)>", line)
    symbol = symbols[-1] if symbols else ""
    return address, symbol, mnemonic


def classify_symbol(symbol: str) -> str:
    """Classify a vector target symbol into ``reset``, ``dummy``, ``default``, or ``other``.

    Parameters:
        symbol: Symbol extracted from the disassembly.

    Returns:
        One of ``"reset"``, ``"dummy"``, ``"default"``, or ``"other"``.
    """
    if symbol.startswith("reset"):
        return "reset"
    if "DummyHandler" in symbol and "__vector" in symbol:
        return "dummy"
    if "__vector_default" in symbol:
        return "default"
    return "other"


def ensure_vector_table_starts_at_zero(start: int) -> None:
    """Ensure that the vector table start address is zero.

    Parameters:
        start: Resolved ``__vectors_start`` address.

    Raises:
        SystemExit: If the start address is not zero.
    """
    if start != 0:
        raise SystemExit(
            "Expected __vectors_start to resolve to address 0 but it was "
            f"{start:#06x}"
        )


def parse_entries(section_lines: Iterable[str]) -> list[tuple[int, str, str, str]]:
    """Collect JMP/RJMP entries from the vector table disassembly lines.

    Parameters:
        section_lines: Iterable of lines believed to contain the vector table.

    Returns:
        A list of tuples ``(address, symbol, mnemonic, original_line)`` for each
        entry.

    Raises:
        SystemExit: If no JMP/RJMP entries are found.
    """
    entries: list[tuple[int, str, str, str]] = []
    for line in section_lines:
        parsed = parse_jmp_line(line)
        if not parsed:
            continue
        address, symbol, mnemonic = parsed
        entries.append((address, symbol, mnemonic, line))

    if not entries:
        raise SystemExit("Did not find any jmp entries while parsing the vector table")

    return entries


def ensure_first_entry_matches_start(entries: Sequence[tuple[int, str, str, str]], start: int) -> None:
    """Ensure the first parsed entry begins at the expected start address.

    Parameters:
        entries: Sequence of parsed vector entries.
        start: Expected address of the first entry.

    Raises:
        SystemExit: If the first entry's address does not match ``start``.
    """
    if entries[0][0] != start:
        raise SystemExit(
            "Expected first vector entry at address 0, but found line:\n" + entries[0][3]
        )


def compute_entry_size(start: int, end: int, entry_count: int) -> int:
    """Compute the byte width of each vector-table entry.

    Parameters:
        start: Start address of the vector table.
        end: End address (exclusive) of the vector table.
        entry_count: Number of decoded entries.

    Returns:
        The size of each entry in bytes (2 or 4).

    Raises:
        SystemExit: If the entry count does not divide the span, the computed
        size is non-positive, or it is not 2 or 4 bytes.
    """
    entry_span = end - start
    if entry_span % entry_count != 0:
        raise SystemExit(
            "Vector table entry count mismatch: the span "
            f"[{start:#06x}, {end:#06x}) is {entry_span} bytes "
            f"but {entry_count} entries were decoded."
        )

    entry_size = entry_span // entry_count
    if entry_size <= 0:
        raise SystemExit(
            f"Computed non-positive vector entry size {entry_size} for span {entry_span}."
        )
    if entry_size not in (2, 4):
        raise SystemExit(
            f"Unsupported vector entry size {entry_size}; expected 2 or 4 bytes per entry."
        )
    return entry_size


def expected_classification(index: int) -> str:
    """Return the expected classification for a vector-table entry index.

    Parameters:
        index: Zero-based index into the vector table.

    Returns:
        ``"reset"`` for index 0, ``"dummy"`` for index 1, ``"default"`` otherwise.
    """
    if index == 0:
        return "reset"
    if index == 1:
        return "dummy"
    return "default"


def format_classification_error(
    expected: str, index: int, symbol: str, line: str
) -> str:
    """Return an error message describing an unexpected vector target classification.

    Parameters:
        expected: Expected classification string.
        index: Index of the vector entry.
        symbol: Symbol actually targeted by the entry.
        line: Original disassembly line.

    Returns:
        A human-readable description of the mismatch.
    """
    if expected == "reset":
        return f"Vector 0 should jump to reset but instead targets '{symbol}'"
    if expected == "dummy":
        return "Vector 1 should jump to DummyHandler::__vector but line was:\n" + line
    return f"Vector {index} should jump to __vector_default but line was:\n" + line


def validate_entry(
    index: int,
    entry: tuple[int, str, str, str],
    start: int,
    entry_size: int,
    expected_mnemonic: str,
) -> None:
    """Validate the address, mnemonic, and classification for a single vector entry.

    Parameters:
        index: Position of the entry in the table.
        entry: Tuple ``(address, symbol, mnemonic, original_line)``.
        start: Start address of the vector table.
        entry_size: Expected byte width of each entry.
        expected_mnemonic: Required mnemonic (``"jmp"``, ``"rjmp"``, or ``"any"``).

    Raises:
        SystemExit: If any property of the entry does not match expectations.
    """
    address, symbol, mnemonic, line = entry
    expected_address = start + index * entry_size
    if address != expected_address:
        raise SystemExit(
            f"Vector {index} should be at byte offset {expected_address:#x} but line was:\n{line}"
        )

    if expected_mnemonic != "any" and mnemonic != expected_mnemonic:
        raise SystemExit(
            f"Vector {index} should use the '{expected_mnemonic}' mnemonic but line was:\n"
            f"{line}"
        )

    classification = classify_symbol(symbol)
    expected = expected_classification(index)
    if classification != expected:
        raise SystemExit(format_classification_error(expected, index, symbol, line))


def validate_entries(
    entries: Sequence[tuple[int, str, str, str]],
    start: int,
    entry_size: int,
    expected_mnemonic: str,
) -> None:
    """Validate all parsed vector-table entries against expectations.

    Parameters:
        entries: Sequence of parsed vector entries.
        start: Start address of the vector table.
        entry_size: Expected byte width of each entry.
        expected_mnemonic: Required mnemonic (``"jmp"``, ``"rjmp"``, or ``"any"``).
    """
    for index, entry in enumerate(entries):
        validate_entry(index, entry, start, entry_size, expected_mnemonic)


def main() -> int:
    """Execute vector-table validation workflow and print a summary report."""
    args = parse_args()
    if not args.binary.exists():
        raise SystemExit(f"Input file '{args.binary}' does not exist")

    start, end = locate_vector_bounds(args.binary)
    ensure_vector_table_starts_at_zero(start)

    section_lines, section_name = load_vectors_section(args.binary, start, end)

    entries = parse_entries(section_lines)
    ensure_first_entry_matches_start(entries, start)

    entry_size = compute_entry_size(start, end, len(entries))

    expected_mnemonic = args.expected_mnemonic
    validate_entries(entries, start, entry_size, expected_mnemonic)

    if section_name != ".vectors":
        print(
            "Note: .vectors section not present in disassembly; using sequential JMPs "
            f"from '{section_name}' as the vector table."
        )

    summary_mnemonic = (
        expected_mnemonic.upper() if expected_mnemonic != "any" else "JMP/RJMP"
    )

    print(
        "Validated {count} interrupt vectors: reset, DummyHandler, "
        "and {defaults} defaults (using {mnemonic}, {entry_size}-byte slots).".format(
            count=len(entries),
            defaults=len(entries) - 2,
            mnemonic=summary_mnemonic,
            entry_size=entry_size,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as err:
        raise SystemExit(str(err)) from err
