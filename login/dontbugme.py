#!/usr/bin/env python
import sys
import argparse
import getpass
import os

try:
    from cryptography.fernet import Fernet
except ModuleNotFoundError:
    print("Missing requirement.\n`pip install cryptography`")
    sys.exit(1)

try:
    import pexpect
except ModuleNotFoundError:
    print("Missing requirement.\n`pip install pexpect`")
    sys.exit(1)


def init(args):
    key = Fernet.generate_key()
    sel = input("Which Role selection: ")
    p = input("aws-azure-login profile: ")
    pw = getpass.getpass("Password:")
    f = Fernet(key)
    e = f.encrypt(pw.encode("utf-8"))
    print("Please run the following command:")
    print(
        f"export LOGIN_SELECTION={sel} LOGIN_PROFILE={p} LOGIN_KEY={key.decode('utf-8')} LOGIN_SECRET={e.decode('utf-8')}"
    )


def do_login(args):
    if not os.environ.get("LOGIN_KEY"):
        print(f"Please run `{sys.argv[0]} init`")
        sys.exit(1)

    while True:
        try:
            print("Logging in .", end="")
            child = pexpect.spawn(
                "aws-azure-login --profile " + os.environ["LOGIN_PROFILE"]
            )
            print(".", end="")

            # child.logfile = sys.stdout.buffer

            n = child.expect([".*Username.*", ".*Password.*"], timeout=6)
            if n == 0:
                print(".", end="")
                child.sendline("")
                child.expect(".*Password.*", timeout=6)

            print(".", end="")
            child.sendline(
                Fernet(os.environ["LOGIN_KEY"].encode("utf-8"))
                .decrypt(os.environ["LOGIN_SECRET"].encode("utf-8"))
                .decode("utf-8")
            )

            child.expect(
                ".*arn:aws:iam::043742107710:role/AWSManagedReadOnlyRole.*", timeout=6
            )
            print(".", end="")
            n = args.select or os.environ.get("LOGIN_SELECTION", "9")
            child.sendline("\033[B" * int(n))

            child.expect(".*Session Duration Hours.*")
            print(".", end="")
            child.sendline("")
            child.expect("Assuming role.*")
            print(".", end="")
            child.wait()
            print(" done")
            sys.exit(0)
        except pexpect.exceptions.TIMEOUT:
            print(" timeout")
            pass


parser = argparse.ArgumentParser(sys.argv[0])
parser.add_argument("-s", dest="select", help="Role selection number")
parser.set_defaults(func=do_login)
sub = parser.add_subparsers(help="sub-command help")
pinit = sub.add_parser("init", help="a help")
pinit.set_defaults(func=init)


if __name__ == "__main__":
    args = parser.parse_args()
    args.func(args)
