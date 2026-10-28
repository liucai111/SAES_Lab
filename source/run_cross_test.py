"""Compare a supplied group-B adapter against local S-AES; never invent external results."""
import argparse
import importlib
import json
import random
from pathlib import Path
from saes.core import encrypt_block, decrypt_block


def main():
    parser = argparse.ArgumentParser(description='跨小组交叉测试：适配器须提供 encrypt_block(p,k)、decrypt_block(c,k)')
    parser.add_argument('--module', required=True, help='例如 other_group_adapter；模块须位于项目目录或 PYTHONPATH')
    parser.add_argument('--count', type=int, default=100)
    parser.add_argument('--output', default='../test_results/external_cross_test.json')
    args = parser.parse_args()
    if args.count < 1:
        parser.error('--count 必须为正数')
    adapter = importlib.import_module(args.module)
    randomizer = random.Random(20261020)
    records = []
    for _ in range(args.count):
        plain, key = randomizer.randrange(65536), randomizer.randrange(65536)
        ours, theirs = encrypt_block(plain, key), adapter.encrypt_block(plain, key)
        local_decrypted, remote_decrypted = decrypt_block(theirs, key), adapter.decrypt_block(ours, key)
        records.append({'plaintext': f'0x{plain:04X}', 'key': f'0x{key:04X}',
                        'cipher_a': f'0x{ours:04X}', 'cipher_b': f'0x{theirs:04X}',
                        'a_decrypt_b': f'0x{local_decrypted:04X}', 'b_decrypt_a': f'0x{remote_decrypted:04X}',
                        'passed': ours == theirs and local_decrypted == remote_decrypted == plain})
    result = {'group_b_module': args.module, 'count': len(records),
              'passed': sum(item['passed'] for item in records), 'records': records}
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(f"{result['passed']}/{result['count']} passed; output: {target}")
    return 0 if result['passed'] == result['count'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
