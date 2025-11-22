import watermarking_cli
import tempfile
from pathlib import Path
import watermarking_cli

def test_cli_methods_subcommand_lists_methods(capsys):
    """
    Call the 'methods' subcommand of the CLI and check that it prints out
    some information about available methods. We don't care about exact
    formatting, only that it runs without crashing and produces output.
    """
    parser = watermarking_cli.build_parser()
    args = parser.parse_args(["methods"])

    # Run the command (this should not raise)
    args.func(args)

    # Capture stdout using capsys (no manual sys.stdout monkeypatching)
    captured = capsys.readouterr()
    out = captured.out.lower()

    # We expect some non-empty output mentioning methods or known names
    assert out.strip() != ""
    assert ("method" in out) or ("toy" in out) or ("eof" in out) or ("fatin" in out)


def test_cli_embed_missing_input_file(tmp_path, capsys):
    parser = watermarking_cli.build_parser()
    out_pdf = tmp_path / "out.pdf"
    args = parser.parse_args([
        "embed",
        "--method", "toy-eof",
        "--key", "k",
        "--secret", "s",
        "--infile", "/non/existing/file.pdf",
        "--outfile", str(out_pdf),
    ])
    # Should not crash with unhandled exception
    try:
        rc = args.func(args)
    except SystemExit as e:
        rc = e.code

    assert rc != 0  # we expect a failure for missing file


def test_cli_embed_and_extract_roundtrip(tmp_path, capsys):
    parser = watermarking_cli.build_parser()

    # Create a small input PDF
    in_pdf = tmp_path / "in.pdf"
    in_pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    out_pdf = tmp_path / "out.pdf"

    secret = "cli-secret"
    key = "cli-key"

    # Embed
    embed_args = parser.parse_args([
        "embed",
        "--method", "toy-eof",
        "--key", key,
        "--secret", secret,
        "--infile", str(in_pdf),
        "--outfile", str(out_pdf),
    ])
    try:
        rc = embed_args.func(embed_args)
    except SystemExit as e:
        rc = e.code
    assert rc == 0
    assert out_pdf.exists()

    # Extract
    extract_args = parser.parse_args([
        "extract",
        "--method", "toy-eof",
        "--key", key,
        "--infile", str(out_pdf),
    ])
    try:
        rc = extract_args.func(extract_args)
    except SystemExit as e:
        rc = e.code
    assert rc == 0

    captured = capsys.readouterr()
    out = captured.out
    assert secret in out