# drupalgeddon2-cli

> A command-line rewrite of the **Drupalgeddon2 (CVE-2018-7600)** proof-of-concept, built as a study exercise while working through the Hack The Box Academy *Attacking Common Applications* module.

> [!WARNING]
> **For authorised security testing and education only.** Running this against systems you do not own or have explicit written permission to test is illegal in most jurisdictions. See [Legal & responsible use](#legal--responsible-use).

> [!NOTE]
> **Implementation written with AI assistance.** See [A note on authorship](#a-note-on-authorship).

---

## Background — why I built this

Drupal is one of the "common applications" covered in HTB Academy's *Attacking Common Applications* module, and CVE-2018-7600 ("Drupalgeddon2") is the canonical unauthenticated-RCE example for it. Rather than copy-paste a one-shot script and move on, I wanted to actually understand the Form API injection that makes the bug work — so I rebuilt the public PoC from the ground up as a learning exercise.

The widely-referenced original, [a2u/CVE-2018-7600](https://github.com/a2u/CVE-2018-7600) by Vitalii Rudnykh, is great for *demonstrating* the bug, but it expects you to edit the payload in-place for each run. In a lab/CTF workflow — re-running against different targets, wanting a repeatable foothold — that gets tedious. This version turns it into a proper CLI tool instead:

- target and command are passed as arguments; no editing source per run
- it plants a tiny PHP web shell automatically (the vulnerable server writes the file itself), giving a stable, re-usable foothold
- you can fire a single command, drop into an interactive pseudo-shell, or just deploy the shell and walk away
- the shell filename and the command parameter are randomised each run, so a repeat run doesn't collide and you don't leave a predictable `cmd=` door open behind you

It's deliberately scoped to a **known, long-patched** vulnerability (disclosed in 2018). The goal was understanding the technique and producing a clean, documented reference implementation — not novel offensive capability.

## A note on authorship

The code in this repository was written with **AI assistance (Anthropic's Claude)** while I worked through the HTB module. I set the design goals and requirements — CLI ergonomics, auto-deploy of the web shell, interactive mode, randomised shell name and parameter — and I reviewed and tested the result. I'm disclosing this because it's the honest thing to do, and because the value here is in the understanding and the engineering decisions rather than authorship of every line.

## What it does

1. Uses the CVE-2018-7600 Form API injection to drop a small PHP web shell onto the target. The vulnerable server decodes and writes the file itself, which sidesteps quoting/escaping problems with the injected command.
2. Lets you run commands through that shell with `--cmd`, or drop into an interactive pseudo-shell with `--shell`.
3. Verifies the shell actually landed and executes (it echoes a random token and checks for it) before reporting success.

## Affected versions

CVE-2018-7600 affects:

- **Drupal 7.x** before **7.58**
- **Drupal 8.x** before **8.5.1** (also 8.3.x < 8.3.9 and 8.4.x < 8.4.6)

This implementation targets the **Drupal 8** Form API vector (the `user/register` AJAX endpoint). Drupal 7 is exploitable through a different endpoint/payload and is **not** handled here.

Patched releases (7.58 / 8.5.1 and later) are not affected.

## Requirements

- Python 3.7+
- [`requests`](https://pypi.org/project/requests/)

```bash
pip install requests
```

## Usage

```bash
# one-off command
python3 drupalgeddon2.py -u http://target/ -c id

# interactive pseudo-shell
python3 drupalgeddon2.py -u http://target/ --shell

# just plant the shell, run nothing
python3 drupalgeddon2.py -u http://target/ --deploy-only

# route through Burp, ignore the proxy's self-signed cert
python3 drupalgeddon2.py -u http://target/ -c id --proxy http://127.0.0.1:8080 -k
```

| Flag | Description |
|------|-------------|
| `-u`, `--url` | **(required)** Target base URL, e.g. `http://target/` |
| `-c`, `--cmd` | Single command to run on the target |
| `--shell` | Drop into an interactive pseudo-shell |
| `--deploy-only` | Only plant the web shell, run nothing |
| `--shell-name` | Filename for the planted shell (default: random `.php`) |
| `--param` | GET parameter name for the shell (default: random md5) |
| `--proxy` | Proxy URL, e.g. `http://127.0.0.1:8080` |
| `-k`, `--insecure` | Disable TLS verification (for self-signed proxy certs) |
| `--timeout` | Per-request timeout in seconds (default: 15) |

## How it works

CVE-2018-7600 is an input-sanitisation failure in Drupal's **Form API**. Drupal represents forms as nested *renderable arrays*, and array keys beginning with `#` are treated as special render properties rather than user data. The patch (SA-CORE-2018-002) added sanitisation to strip these `#`-prefixed keys out of user-supplied input.

Before the patch, an unauthenticated attacker could inject render properties into a form element that gets processed by Drupal's AJAX handler. Submitting properties such as:

- `#post_render` — a list of callables Drupal invokes after rendering, and
- `#markup` — the argument passed to them

against the user-registration form's `mail` element causes Drupal to call an arbitrary PHP function (here, `exec`) with attacker-controlled input during the render step — i.e. remote code execution, with no authentication required.

This PoC uses that primitive to base64-encode a one-line PHP shell locally, have the server decode it to a file in the webroot, and then interact with that file over normal GET requests.

## Detection & remediation

If you're on the defending side of this:

**Remediation**
- Upgrade to Drupal **7.58 / 8.5.1** or later (apply SA-CORE-2018-002). This is the only real fix.
- If immediate patching is impossible, the Drupal Security Team published a mitigation patch at disclosure time — but upgrading is strongly preferred.

**Detection ideas**
- Inspect POST bodies to form/AJAX endpoints for render-array keys: `#post_render`, `#markup`, `#type`, `#lazy_builder`, etc. Legitimate form submissions don't contain these.
- Flag requests to `…/user/register?element_parents=…&_wrapper_format=drupal_ajax` carrying suspicious parameters.
- Correlate a POST to an AJAX form endpoint with a subsequent GET to a newly-created `.php` file in the webroot.
- Watch for unexpected file creation in the Drupal webroot, and for short single-parameter PHP files (`system($_GET[...])` shells).
- These behaviours are straightforward to encode as Suricata/Snort signatures or Sigma rules over web-server logs.

## Credits

- Original PoC and the core technique: **Vitalii Rudnykh** — [a2u/CVE-2018-7600](https://github.com/a2u/CVE-2018-7600)
- Vulnerability disclosure: **Drupal Security Team** — [SA-CORE-2018-002](https://www.drupal.org/sa-core-2018-002)
- Technique deep-dives that informed this rewrite: the Check Point and Ambionics research write-ups on Drupalgeddon2
- This CLI rewrite: me, with AI assistance (see [A note on authorship](#a-note-on-authorship))

## Legal & responsible use

This tool is published for **education** and for **authorised** security testing — your own lab environments, HTB/CTF targets, or systems you have explicit written permission to assess. Unauthorised access to computer systems is a crime under laws such as the UK Computer Misuse Act 1990, the US Computer Fraud and Abuse Act, and equivalents elsewhere. You are solely responsible for how you use it. The author accepts no liability for misuse or for any damage caused.

## License
MIT
