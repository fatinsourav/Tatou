import pytest
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
    rc = args.func(args)
    # Many CLI funcs return 0; be tolerant and only require non-crash
    assert rc in (None, 0)

    # Capture stdout using capsys
    captured = capsys.readouterr()
    out = captured.out.lower()

    # We expect some non-empty output mentioning methods or known names
    assert out.strip() != ""
    assert ("method" in out) or ("toy" in out) or ("eof" in out) or ("fatin" in out)


def test_cli_embed_missing_input_file(tmp_path):
    """
    Calling 'embed' with a non-existing input file should raise FileNotFoundError.
    This exercises the error-handling path in cmd_embed/load_pdf_bytes.
    """
    parser = watermarking_cli.build_parser()
    out_pdf = tmp_path / "out.pdf"

    # Note: 'embed' takes positional input/output, NOT --infile/--outfile
    args = parser.parse_args([
        "embed",
        "/non/existing/file.pdf",   # input (does not exist)
        str(out_pdf),               # output path
        "--method", "toy-eof",
        "--key", "k",
        "--secret", "s",
    ])

    # cmd_embed should try to open the input and trigger FileNotFoundError
    with pytest.raises(FileNotFoundError):
        args.func(args)


def test_cli_embed_and_extract_roundtrip(tmp_path, capsys):
    """
    Full roundtrip:
    - create a tiny valid PDF
    - embed a secret with toy-eof
    - extract the secret again
    """
    parser = watermarking_cli.build_parser()

    # Create a small input PDF
    in_pdf = tmp_path / "in.pdf"
    in_pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    out_pdf = tmp_path / "out.pdf"

    secret = "cli-secret"
    key = "cli-key"

    # --- Embed ---
    embed_args = parser.parse_args([
        "embed",
        str(in_pdf),         # input
        str(out_pdf),        # output
        "--method", "toy-eof",
        "--key", key,
        "--secret", secret,
    ])
    rc = embed_args.func(embed_args)
    assert rc in (None, 0)
    assert out_pdf.exists()

    # --- Extract ---
    extract_args = parser.parse_args([
        "extract",
        str(out_pdf),
        "--method", "toy-eof",
        "--key", key,
    ])
    rc2 = extract_args.func(extract_args)
    assert rc2 in (None, 0)

    # Capture output and ensure the secret is printed
    captured = capsys.readouterr()
    out = captured.out
    assert secret in out
