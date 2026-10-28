"""Command line: python -m saes --help."""
import argparse
import json
import sys
from pathlib import Path
from .service import execute, parse_pairs
from .attack import meet_in_the_middle


def main(argv=None):
    parser = argparse.ArgumentParser(description="S-AES 五关实验工具")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for operation in ("block", "ascii", "double", "triple", "cbc-blocks", "cbc-text"):
        sub = subparsers.add_parser(operation)
        sub.add_argument("--data", required=True, help="文本、二进制、0x十六进制；参见文档")
        sub.add_argument("--key", required=True, help="16/32/48 位二进制或 0x 十六进制")
        sub.add_argument("--decrypt", action="store_true")
        sub.add_argument("--iv", default="0x0000", help="CBC 解密必须与加密端相同")
        sub.add_argument("--no-padding", action="store_true", help="仅 ASCII 模式：原始偶数字节分组")
        sub.add_argument("--encoding", choices=("hex", "base64", "latin1"), default="hex")
    attack = subparsers.add_parser("mitm")
    attack.add_argument("--pairs-file", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "mitm":
            result = meet_in_the_middle(parse_pairs(args.pairs_file.read_text(encoding="utf-8")))
            result["candidates"] = [{"key1": f"0x{k1:04X}", "key2": f"0x{k2:04X}",
                                     "combined_binary": f"{k1:016b}{k2:016b}"}
                                    for k1, k2 in result["candidates"]]
        else:
            result = execute(args.command, args.data, args.key, decrypt=args.decrypt,
                             iv=args.iv, padding=not args.no_padding, encoding=args.encoding)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except (ValueError, OSError) as error:
        print(f"输入错误: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
