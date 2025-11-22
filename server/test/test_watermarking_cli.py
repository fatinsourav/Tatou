import argparse
import io
import sys

import watermarking_cli


def test_cli_methods_subcommand_lists_methods(capsys, monkeypatch):
    parser = watermarking_cli.build_parser()
    args = parser.parse_args(["methods"])

    # capture stdout
    saved_stdout = sys.stdout
    try:
        sys.stdout = io.TextIOBase()  # dummy, capsys will still capture writes
    except Exception:
        pass  # fall back; capsys still works

    # run the command
    args.func(args)

    # inspect captured output
    captured = capsys.readouterr()
    out = captured.out.lower()
    assert "methods" in out or "toy-eof" in out or "fatin" in out
