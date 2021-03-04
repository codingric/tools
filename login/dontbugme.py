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
import boto3

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
    def __init__(self, config, args):

        self._config = config
        self._args = vars(args)

        self.progress("Starting", 0)
        self._child = pexpect.spawn(
            f"aws-azure-login --profile {config['profile']}",
            # logfile=sys.stdout,
            encoding="utf-8",
        )

        self._break = False
        try:
            self.loop()
        except KeyboardInterrupt:
            print("Canceled login.                     ")

    def loop(self):
        patterns = [
            ".*Username.*",
            "(?i)password",
            "We've.*",
            ".*Role:.*Use",
            ".*Session Duration Hours",
            ".*Assuming role",
        ]
        self.progress("Logging in", 0)
        n = self._child.expect(patterns[1::-1], timeout=10)
        if n == 1:
            self.progress("Logging in", 1)
            self._child.sendline("")
            self._child.expect(patterns[1], timeout=5)

        self.password()
        self.progress("Logged in", 2)
        n = self._child.expect(patterns[3:1:-1], timeout=5)
        if n == 1:
            self.progress("MFA approval required.", 3)
            self._child.expect(patterns[3], timeout=30)
        self.progress("Role selected", 4)
        self.role()
        self._child.expect(patterns[4], timeout=5)
        self._child.sendline("1")
        self._child.expect(patterns[5], timeout=2)
        self.progress("Assuming role.", 5)
        self._child.wait()
        self.progress("Authenticated as " + self.get_aws_sts(), 6)
        print()

    def password(self):
        self._child.sendline(
            Fernet(key()).decrypt(self._config["secret"].encode("utf8")).decode("utf8")
        )

    def role(self):
        self._child.sendline(
            "\033[B" * int(self._args.get("role") or self._config.get("role", 9))
        )

    def progress(self, text, counter=0, max=6):
        print(
            " [{0}{1}] {2: <24}\r".format("#" * counter, "-" * (max - counter), text),
            end="",
            flush=True,
        )

    def get_aws_sts(self):
        response = boto3.client("sts").get_caller_identity()
        return response["Account"] + "/" + response["Arn"].split("/")[1]


def do_login(args):
    config = load_config(args.config)
    tries = 0

    while tries < 5:
        tries += 1
        try:
            Login(config, args)
            return
        except pexpect.exceptions.TIMEOUT:
            print("Timeout.")
            pass


parser = argparse.ArgumentParser(sys.argv[0])
parser.add_argument("-r", dest="role", help="Role selection number")
parser.add_argument("--config", dest="config", default="~/.dontbugme.yaml")
parser.set_defaults(func=do_login)
sub = parser.add_subparsers(help="sub-command help")
pinit = sub.add_parser("init", help="a help")
pinit.set_defaults(func=init)


if __name__ == "__main__":
    args = parser.parse_args()
    args.func(args)


# We've sent a notification to your mobile device. Please open the Microsoft Authenticator app to respond.
