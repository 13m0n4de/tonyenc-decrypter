#!/usr/bin/env python3

import binascii
import os
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress

console = Console()


def decrypt_content(
    encrypted_content: bytes, key: bytes, header: bytes
) -> Optional[bytearray]:
    if encrypted_content[: len(header)] != header:
        return None

    data = bytearray(encrypted_content[len(header) :])

    if data:
        key_idx = 0
        key_len = len(key)
        for data_idx in range(len(data)):
            if (data_idx & 1) != 0:
                key_idx = (key[key_idx] + data_idx + key_idx) & (key_len - 1)
                data[data_idx] = key[key_idx] ^ (~data[data_idx] & 0xFF)

    return data


def decrypt_file(
    input_file: Path,
    output_file: Path,
    key: bytes,
    header: bytes,
    overwrite: bool = False,
) -> bool:
    try:
        if not overwrite and output_file.exists():
            console.print(
                f"[bold yellow][!][/] Skipping {input_file}: "
                f"Output file {output_file} already exists"
            )
            return False

        encrypted_content = input_file.read_bytes()

        if decrypted_content := decrypt_content(encrypted_content, key, header):
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_bytes(decrypted_content)
            return True

    except Exception as e:
        console.print(f"[bold red][-][/] Error decrypting {input_file}: {str(e)}")

    return False


def process_directory(
    input_dir: Path,
    output_dir: Path,
    key: bytes,
    header: bytes,
    extension: str = ".php",
    overwrite: bool = False,
) -> tuple:
    files_to_process = []
    for root, _, files in os.walk(input_dir):
        root_path = Path(root)
        for file in files:
            if file.endswith(extension):
                input_file = root_path / file
                rel_path = input_file.relative_to(input_dir)

                if output_dir != input_dir:
                    output_file = output_dir / rel_path
                else:
                    output_file = input_file.with_suffix(input_file.suffix + ".decoded")

                files_to_process.append((input_file, output_file))

    success_count = 0
    total_count = len(files_to_process)

    if total_count == 0:
        console.print(f"[bold yellow][!][/] No files with extension {extension} found")
        return 0, 0

    with Progress() as progress:
        task = progress.add_task("[bold cyan][*][/] Decrypting...", total=total_count)

        for idx, (input_file, output_file) in enumerate(files_to_process):
            progress.update(
                task, description=f"[bold blue][*][/] Decrypting {input_file.name}"
            )

            if decrypt_file(input_file, output_file, key, header, overwrite):
                success_count += 1

            progress.update(task, completed=idx + 1)

    return success_count, total_count


@click.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--key", required=True, help="Decryption key as hex string")
@click.option("--header", required=True, help="File header as hex string")
@click.option("--ext", default=".php", help="File extension to process (default: .php)")
@click.option(
    "-o", "--output", type=click.Path(), help="Output path for decrypted file(s)"
)
@click.option(
    "--overwrite", is_flag=True, help="Overwrite output files if they already exist"
)
def main(input_path, output, key, header, ext, overwrite):
    try:
        try:
            key_bytes = binascii.unhexlify(key)
            header_bytes = binascii.unhexlify(header)
        except binascii.Error:
            console.print(
                "[bold red][-][/] Error: Invalid hex string for key or header"
            )
            return

        input_path = Path(input_path)
        output_path = Path(output) if output else None

        # Handle file mode
        if input_path.is_file():
            if not output_path:
                # If output not specified, place in same directory
                # with .decoded extension
                output_file = input_path.with_suffix(input_path.suffix + ".decoded")
            elif output_path.exists() and output_path.is_dir():
                # If output is a directory, place as output_dir/input_file_name
                output_file = output_path / input_path.name
            else:
                # If output is a file, use the specified path
                output_file = output_path

            console.print(f"[bold green][+][/] Decrypting file: [bold]{input_path}[/]")
            if decrypt_file(
                input_path, output_file, key_bytes, header_bytes, overwrite
            ):
                console.print(
                    f"[bold green][+][/] Success: Decrypted to [bold]{output_file}[/]"
                )
            else:
                console.print(
                    f"[bold red][-][/] Failed: Could not decrypt {input_path}"
                )

        # Handle directory mode
        elif input_path.is_dir():
            # Check if output is specified as a file
            if output_path and output_path.exists() and not output_path.is_dir():
                console.print(
                    "[bold red][-][/] Error: When input is a directory, "
                    "output must be a directory"
                )
                return

            # If output is not specified, use input directory
            if not output_path:
                output_path = input_path
            # If output path doesn't exist, create it
            elif not output_path.exists():
                output_path.mkdir(parents=True, exist_ok=True)

            console.print(
                "[bold blue][*][/] Recursively decrypting files in: "
                f"[bold]{input_path}[/]"
            )

            success_count, total_count = process_directory(
                input_path, output_path, key_bytes, header_bytes, ext, overwrite
            )

            console.print(
                "[bold green][+][/] Decryption complete: "
                f"{success_count}/{total_count} files"
            )

    except Exception as e:
        console.print_exception()
        console.print(f"[bold red][-][/] Error: {str(e)}")


if __name__ == "__main__":
    main()
