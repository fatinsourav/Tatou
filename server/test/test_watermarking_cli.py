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
