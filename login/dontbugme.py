#!/usr/bin/env python
import subprocess
from datetime import datetime, timezone, timedelta
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
from zoneinfo import ZoneInfo


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
    r = input("default role position: ")
    pw = getpass.getpass("Password:")
    f = Fernet(key())
    e = f.encrypt(pw.encode("utf-8"))
    config = {"secret": e.decode("utf8"), "profile": p, "roles": {"default": r}}
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
    def __init__(self, config, args, daemon):

        self._config = config
        self._args = vars(args)
        self._daemon = daemon

        self.progress("Starting", 0)
        self._child = pexpect.spawn(
            f"aws-azure-login --profile {config['profile']}{' -m gui' if args.gui else ''}",
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
        if not self._args["gui"]:
            self.progress("Logging in", 0)
            n = self._child.expect(patterns[1::-1], timeout=15)
            if n == 1:
                self.progress("Logging in", 1)
                self._child.sendline("")
                self._child.expect(patterns[1], timeout=5)

            self.password()
            self.progress("Logged in", 2)
        n = self._child.expect(
            patterns[3:1:-1], timeout=5 if not self._args["gui"] else 60
        )
        if n == 1:
            if self._daemon:
                print("Need to exit daemon mode.")
                sys.exit(0)
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
        n = int(self._config["roles"]["default"])
        if self._args.get("role"):
            if self._args.get("role").isnumeric():
                n = int(self._args.get("role"))
            else:
                try:
                    n = int(self._config["roles"][self._args.get("role")])
                except:
                    pass

        self._child.sendline("\033[B" * int(n))

    def progress(self, text, counter=0, max=6):
        print(
            "\r\033[K [{0}{1}] {2} ".format("#" * counter, "-" * (max - counter), text),
            end="",
            flush=True,
        )

    def get_aws_sts(self):
        response = boto3.client("sts").get_caller_identity()
        return response["Account"] + "/" + response["Arn"].split("/")[1]


def do_login(args, daemon=False):
    if args.check:
        print(f"{expiry()} ({int(time_left().total_seconds() / 60)} mins)")
        return

    config = load_config(args.config)
    tries = 0

    while tries < 5:
        tries += 1
        try:
            Login(config, args, daemon=daemon)
            return
        except pexpect.exceptions.TIMEOUT:
            print("\rTimeout.\033[K")
            pass


def do_daemon(args, config):
    while True:
        if soon_to_expire():
            do_login(args, True)
        time.sleep(300)


def init_daemon(args):
    config = load_config(args.config)
    try:
        import daemon
    except ModuleNotFoundError:
        print("Missing requirement.\n`pip install python-daemon`")
        sys.exit(1)
    with daemon.DaemonContext():
        do_daemon(args, config)


def expiry():
    session = (
        subprocess.check_output("aws configure get aws_expiration", shell=True)
        .decode("utf8")
        .strip()
    )
    expires = (
        datetime.strptime(session, "%Y-%m-%dT%H:%M:%S.000Z")
        .replace(tzinfo=timezone.utc)
        .astimezone(tz=None)
    )
    return expires


def time_left():
    now = datetime.now().replace(tzinfo=ZoneInfo("Australia/Melbourne"))
    return expiry() - now


def soon_to_expire(mins=15):
    now = datetime.now().replace(tzinfo=ZoneInfo("Australia/Melbourne"))
    return now > (expiry() - timedelta(minutes=mins))


parser = argparse.ArgumentParser(sys.argv[0])
parser.add_argument(
    "-c",
    "--config",
    dest="config",
    default="~/.dontbugme.yaml",
    help="Override default config file location",
)
parser.add_argument("-r", dest="role", help="Role position")
parser.add_argument(
    "-g",
    help="Start with gui, used to allow 14day MFA approval",
    dest="gui",
    default=False,
    action="store_true",
)
parser.add_argument(
    "-e",
    "--expiry",
    dest="check",
    action="store_true",
    help="Check when session will expire",
)
parser.set_defaults(func=do_login)
sub = parser.add_subparsers(help="")
pinit = sub.add_parser("init", help="Initialise config files")
pinit.set_defaults(func=init)
pdaemon = sub.add_parser("daemon", help="Start in daemon mode")
pdaemon.set_defaults(func=init_daemon)


if __name__ == "__main__":
    args = parser.parse_args()
    args.func(args)