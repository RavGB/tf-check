# tf-check

A quick first-pass scan of Terraform files for common safety and cost risks, explained in plain words: security groups open to the whole internet, public storage buckets, databases anyone can reach, secrets written into the code, and overly broad IAM policies.

**This is a linter-style helper, not a replacement for a real review.** It is the fast pass you run before the careful one, not instead of it.

## How it reads your files (the honest limitation)

tf-check **reads blocks and attributes as text; it does not evaluate Terraform.** There is no HCL evaluation, no variable or function resolution, and no plan. It finds top-level `resource` and `data` blocks by matching braces (ignoring braces inside strings, comments, and heredocs), reads the sub-blocks and `name = value` attributes inside them, and applies the rules below to that text.

What that means in practice:

- A risk built by a variable, a function like `jsonencode` fed from variables, a loop, or a module in another folder can be missed.
- An attribute inside a nested block is treated as part of the enclosing block, so a rule can occasionally comment on a value that belongs to a sub-block.
- A clean result means "nothing common was spotted in the text", never "this setup is safe".

Always follow up with a real review before relying on Terraform files.

## Rules

| Rule | Severity | Why it matters |
| --- | --- | --- |
| OPEN-INGRESS | critical when the open range covers port 22 or 3389, high otherwise | A security group open to `0.0.0.0/0` or `::/0` lets the whole internet reach those ports, and open SSH or Remote Desktop ports are attacked within minutes. |
| PUBLIC-S3 | high | A bucket with a `public-read` or `public-read-write` ACL can be read by anyone, no account needed. |
| S3-NO-PUBLIC-ACCESS-BLOCK | medium | The public access block is the safety net that keeps a bucket private even if a policy or ACL is set wrong later; a bucket without one is one mistake from exposure. |
| PUBLIC-DATABASE | critical | A database with `publicly_accessible = true` can be reached from the internet instead of only from inside the network. |
| UNENCRYPTED-DATABASE | medium | If `storage_encrypted` is false, the data is readable to anyone who gets the storage; if it is not set at all, you are relying on account defaults you may not control. |
| HARDCODED-SECRET | critical | A password, secret, client secret, or API key written as a plain string in the code is known to everyone who can read the repository, forever, including in its history. The report masks the value as `"***"` and never prints it. |
| BROAD-IAM | high | A policy allowing `*` or a whole service (like `s3:*`) on every resource turns one leaked credential into access to everything that action touches. This rule is a targeted text check for an Allow statement combining a broad action with `"Resource": "*"`. |

## Build

```sh
go build -o tf-check .
```

## Usage

```sh
# Scan the current folder, fail only on critical findings (the default)
./tf-check

# Scan a folder and fail on high findings too
./tf-check --path ./infra --fail-on high

# Machine-readable report, also saved to a file
./tf-check --path ./infra --json --output report.json
```

The scan walks the folder recursively for `.tf` files, skipping `.git` and `.terraform` directories (vendored modules are not your code to fix). A single `.tf` file can also be given as `--path`.

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--path` | `.` | Directory (or single file) to scan |
| `--fail-on` | `critical` | Lowest severity that makes the run exit 1: `critical`, `high`, or `medium` |
| `--json` | off | Print the report as JSON |
| `--output` | | Also write the report to this file |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` |
| 2 | Usage error (bad flag value, unreadable path) or no `.tf` files found |

## Sample run

Against a demo folder holding one risky file (`risky.tf`: an SSH port open to the world and a public database with a written-in password) and one clean file (`clean.tf`: a bucket with its public access block, a private encrypted database using a variable for its password):

```text
$ tf-check --path /tmp/tf-demo
tf-check: scanned 2 file(s) under /tmp/tf-demo

CRITICAL (3)
  OPEN-INGRESS  /tmp/tf-demo/risky.tf:4  aws_security_group.web
    Ingress allows traffic from any address (0.0.0.0/0) to ports 22-22. That range includes SSH (port 22), so anyone on the internet can try to connect to it.
  PUBLIC-DATABASE  /tmp/tf-demo/risky.tf:13  aws_db_instance.main
    publicly_accessible is true, so this database can be reached from the internet. Databases should sit on private subnets and be reached through the application or a bastion.
  HARDCODED-SECRET  /tmp/tf-demo/risky.tf:17  aws_db_instance.main
    Attribute "password" is set to a hardcoded value ("***") in the code. Anyone who can read this repository knows the secret; move it to a variable fed from a secrets store.

MEDIUM (1)
  UNENCRYPTED-DATABASE  /tmp/tf-demo/risky.tf:13  aws_db_instance.main
    storage_encrypted is not set on this database, so whether its storage is encrypted depends on account defaults. Set it to true to be sure.

Summary: 3 critical, 0 high, 1 medium across 2 file(s).
```

Exit code 1 (critical findings meet the default `--fail-on critical`). Scanning only the clean file reports "No findings" and exits 0.

## License

MIT. See [LICENSE](LICENSE).
