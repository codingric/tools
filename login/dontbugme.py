#!/usr/bin/env python
import sys
import argparse
import getpass
import os
import time
from pexpect.exceptions import TIMEOUT
import yaml
import base64
import hashlib

KEY_DOWN = "\x1b[B"

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


def load_config(config):
    try:
        with open(os.path.expanduser(config), "r") as f:
            data = yaml.safe_load(f)
        data["key"] = key()
        return data
    except FileNotFoundError:
        print(f"Please run `{sys.argv[0]} init`")
        sys.exit(1)


def key():
    m = hashlib.sha256()
    k = os.environ["PATH"].encode("utf8")
    m.update(k)
    k = m.hexdigest()[:24]
    k = base64.urlsafe_b64encode(k.encode("utf8"))
    k = base64.urlsafe_b64encode(k)
    return k


def init(args):
    p = input("aws-azure-login profile: ")
    pw = getpass.getpass("Password:")
    f = Fernet(key())
    e = f.encrypt(pw.encode("utf-8"))
    config = {"secret": e.decode("utf8"), "profile": p}
    with open(
        os.open(
            os.path.expanduser(args.config),
            os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
            0o600,
        ),
        "w",
    ) as f:
        yaml.dump(config, f)


class Login(object):
    def __init__(self, config):
        self._config = config
        self._child = pexpect.spawn(
            f"aws-azure-login --profile {config['profile']}",
            # logfile=sys.stdout,
            encoding="utf-8",
        )

        self._break = False
        self.loop()

    def loop(self):
        patterns = [
            ".*Username.*",
            "(?i)password",
            "We've.*",
            ".*Role:.*Use",
            ".*Session Duration Hours",
            ".*Assuming role",
        ]
        n = self._child.expect(patterns[1::-1], timeout=10)
        if n == 1:
            self._child.sendline("")
            print("Username selected. ")
            self._child.expect(patterns[1], timeout=5)

        self.password()
        n = self._child.expect(patterns[3:1:-1], timeout=5)
        if n == 1:
            print("MFA approval required.")
            self._child.expect(patterns[3], timeout=30)

        self.role()
        self._child.expect(patterns[4], timeout=5)
        self._child.sendline("1")
        self._child.expect(patterns[5], timeout=2)
        print("Assuming role.")
        self._child.wait()

    def password(self):
        self._child.sendline(
            Fernet(key()).decrypt(self._config["secret"].encode("utf8")).decode("utf8")
        )
        print("Password sent.")

    def role(self):
        self._child.sendline("\033[B" * 9)
        print("Role selected.")


def do_login(args):
    config = load_config(args.config)
    tries = 0

    while tries < 5:
        tries += 1
        try:
            Login(config)
            return
        except pexpect.exceptions.TIMEOUT:
            print("Timeout.")
            pass


parser = argparse.ArgumentParser(sys.argv[0])
parser.add_argument("-s", dest="select", help="Role selection number")
parser.add_argument("-v", dest="verbose", default=False, action="store_true")
parser.add_argument("--config", dest="config", default="~/.dontbugme.yaml")
parser.set_defaults(func=do_login)
sub = parser.add_subparsers(help="sub-command help")
pinit = sub.add_parser("init", help="a help")
pinit.set_defaults(func=init)


if __name__ == "__main__":
    args = parser.parse_args()
    args.func(args)


# We've sent a notification to your mobile device. Please open the Microsoft Authenticator app to respond.
