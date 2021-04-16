#!/usr/bin/env python3.9
import sys

if sys.version_info.major < 3 or sys.version_info.minor < 9:
    print("Sorry this script requires python 3.9+")
    sys.exit(1)

import subprocess
from datetime import datetime, timezone, timedelta
import argparse
import getpass
import os
import re
import time

import base64
import hashlib


KEY_DOWN = "\x1b[B"

PROFILE = os.environ.get("AWS_DEFAULT_PROFILE")

MISSING = []


try:
    import boto3
except ModuleNotFoundError:
    MISSING.append("boto")

try:
    import yaml
except ModuleNotFoundError:
    MISSING.append("pyyaml")

try:
    from cryptography.fernet import Fernet
except ModuleNotFoundError:
    MISSING.append("cryptography")

try:
    import pexpect
    from pexpect.exceptions import TIMEOUT
except ModuleNotFoundError:
    MISSING.append("pexpect")

if MISSING:
    if "install" in sys.argv:
        for n in MISSING:
            subprocess.check_call(f"pip install {n}", shell=True, stdout=sys.stdout)
        sys.exit(0)
    else:
        print("You have the following modules missing:")
        for n in MISSING:
            print(f"- {n}")
        print(f"\nTo install run `{sys.argv[0]} install`")
        sys.exit(1)


class NoConfigFile(Exception):
    pass


class InvalidPassword(Exception):
    pass


def aws_configure_get(key):
    global PROFILE
    return (
        subprocess.check_output(
            f"aws configure get {key} --profile {PROFILE}", shell=True
        )
        .decode("utf8")
        .strip()
    )


def aws_configure_set(key, value):
    global PROFILE
    subprocess.check_output(
        f"aws --profile {PROFILE} configure set {key} {value}", shell=True
    )


def load_config(config):
    try:
        with open(os.path.expanduser(config), "r") as f:
            data = yaml.safe_load(f)
        data["key"] = key()
        return data
    except FileNotFoundError:
        raise NoConfigFile(f"Please run `{sys.argv[0]} config`")


def key():
    m = hashlib.sha256()
    k = os.environ["PATH"].encode("utf8")
    m.update(k)
    k = m.hexdigest()[:24]
    k = base64.urlsafe_b64encode(k.encode("utf8"))
    k = base64.urlsafe_b64encode(k)
    return k


def config_roles(args, config):
    roles = config.get("roles", {})

    q = 0
    done = False
    while True:
        o = len(roles)
        zz = (
            "[add: +prod=11, remove: -meta, default: *dev, save: blank]"
            if not done
            else ""
        )
        print(f"Roles: {zz}\n------")
        f = True
        for k, v in roles.items():
            print(f"  {k}: {v}{' (default)' if f else ''}")
            f = False
        if len(roles) == 0:
            print("None.")
        print("------")
        if done:
            break
        cmnd = input("Command: ")
        for x in range(o + (4 if o > 0 else 5)):
            print("\u001b[1A\r\033[K", end="")
        if not cmnd:
            done = True
            continue
        if cmnd[0] == "-":
            if cmnd[1:] in roles:
                del roles[cmnd[1:]]
        elif cmnd[0] == "+":
            if "=" in cmnd:
                k, n = cmnd[1:].split("=")
                roles[k] = n
        elif cmnd[0] == "*":
            if cmnd[1:] in roles:
                n = roles.pop(cmnd[1:])
                l = list(roles.items())
                l.insert(0, (cmnd[1:], n))
                roles = dict(l)

    if len(roles) < 1:
        r = input(
            f"default role position{' ('+str(roles['default'])+')' if 'default' in roles else ''}: "
        )
        if r:
            roles["default"] = r
    return roles


def config(args):
    global PROFILE
    try:
        config = load_config(args.config)
    except NoConfigFile:
        config = {}

    p = input(
        f"aws profile{' ('+config['profile']+')' if 'profile' in config else ''}: "
    )
    if p:
        config["profile"] = p
        PROFILE = PROFILE or p

    config["roles"] = config_roles(args, config)

    pw = getpass.getpass(f"Password{ ' (*****)' if 'secret' in config else ''}:")

    if pw:
        f = Fernet(key())
        e = f.encrypt(pw.encode("utf-8"))
        config["secret"] = e.decode("utf8")

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
        global PROFILE
        self._config = config
        self._args = vars(args)
        self._daemon = daemon

        self.progress("Starting", 0)
        self._child = pexpect.spawn(
            f"aws-azure-login --profile {PROFILE}{' -m gui' if args.gui else ''}",
            # logfile=sys.stdout,
            encoding="utf-8",
        )

        self._break = False
        try:
            self.loop()
        except KeyboardInterrupt:
            print("\r\033[KCanceled login.\033[K")

    def loop(self):
        patterns = [
            ".*Username.*",
            "(?i)password",
            "We've.*|Open your Microsoft Authenticator.*",
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
        p = [patterns[3], patterns[2], pexpect.TIMEOUT]
        n = self._child.expect(p, timeout=5 if not self._args["gui"] else 60)
        if n == 2:
            z = self._child.expect([patterns[1]], timeout=1)
            raise InvalidPassword()

        self.progress(f"Logged in ({n})", 2)
        if n == 1:
            if self._daemon:
                print("Need to exit daemon mode.")
                sys.exit(0)
            self.progress("MFA approval required.", 3)
            self._child.expect(patterns[3], timeout=30)
        self.role()
        self.progress("Role selected", 4)
        self._child.expect(patterns[4], timeout=5)
        self._child.sendline("1")
        self._child.expect(patterns[5], timeout=2)
        self.progress("Assuming role.", 5)
        self._child.wait()
        role = get_aws_sts()
        aws_configure_set("dontbugme_role", role)
        self.progress(f"Authenticated as {role}", 6)
        print()

    def password(self):
        p = Fernet(key()).decrypt(self._config["secret"].encode("utf8")).decode("utf8")
        self._child.sendline(p)

    def role(self):
        n = int(list(self._config["roles"].values())[0])
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


def get_aws_sts():
    global PROFILE
    response = (
        boto3.session.Session(profile_name=PROFILE).client("sts").get_caller_identity()
    )
    return response["Account"] + "/" + response["Arn"].split("/")[1]


def do_login(args, daemon=False):
    if args.check:
        min_left = int(time_left().total_seconds() / 60)
        whoami = aws_configure_get("dontbugme_role") or "Noone"
        print(f"{expiry()} ({min_left} mins) - {whoami}")
        return

    try:
        config = load_config(args.config)
    except NoConfigFile as e:
        print(str(e))
        sys.exit(1)

    if args.role and not args.role.isdigit() and args.role not in config["roles"]:
        print(f"Role can only be one of: {' '.join(list(config['roles'].keys()))}")
        sys.exit(1)

    tries = 0

    while tries < 5:
        tries += 1
        try:
            Login(config, args, daemon=daemon)
            return
        except pexpect.exceptions.TIMEOUT:
            print("\rTimeout.\033[K")
            pass
        except InvalidPassword:
            print("\rIncorrect password, run `dontbugme config`.\033[K")
            sys.exit(1)
    sys.exit(2)


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
    expires = (
        datetime.strptime(
            aws_configure_get("aws_expiration"),
            "%Y-%m-%dT%H:%M:%S.000Z",
        )
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
parser.add_argument(
    "-p", "--profile", dest="profile", help="override config AWS Profile to use"
)
parser.set_defaults(func=do_login)
sub = parser.add_subparsers(help="")
pinit = sub.add_parser("config", help="Configure settings")
pinit.set_defaults(func=config)
pdaemon = sub.add_parser("daemon", help="Start in daemon mode")
pdaemon.set_defaults(func=init_daemon)


if __name__ == "__main__":
    args = parser.parse_args()
    PROFILE = PROFILE or args.profile
    args.func(args)