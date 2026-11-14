package main

import (
	"strings"
	"testing"
)

// scanStrings builds a project from in-memory files (name → contents)
// in the order given by names, without touching the filesystem.
func scanStrings(files map[string]string, names ...string) *Project {
	p := &Project{}
	for i, name := range names {
		doc, blocks := parseFile(name, files[name], i)
		p.Files = append(p.Files, doc)
		p.Blocks = append(p.Blocks, blocks...)
	}
	return p
}

func findingsFor(t *testing.T, src string) []Finding {
	t.Helper()
	return runRules(scanStrings(map[string]string{"main.tf": src}, "main.tf"))
}

func onlyRule(fs []Finding, rule string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

// --- OPEN-INGRESS -----------------------------------------------------------

func TestOpenIngressSSHIsCritical(t *testing.T) {
	fs := onlyRule(findingsFor(t, `resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`), "OPEN-INGRESS")
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	if fs[0].Severity != SevCritical {
		t.Errorf("severity = %v, want critical for SSH", fs[0].Severity)
	}
	if fs[0].Line != 2 {
		t.Errorf("line = %d, want 2 (the ingress block)", fs[0].Line)
	}
}

func TestOpenIngressWebPortIsHighNotCritical(t *testing.T) {
	fs := onlyRule(findingsFor(t, `resource "aws_security_group" "web" {
  ingress {
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`), "OPEN-INGRESS")
	if len(fs) != 1 || fs[0].Severity != SevHigh {
		t.Fatalf("findings = %+v, want one high", fs)
	}
}

func TestOpenIngressNegatives(t *testing.T) {
	cases := map[string]string{
		"private cidr": `resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["10.0.0.0/8"]
  }
}`,
		"open egress only": `resource "aws_security_group" "web" {
  egress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}`,
		"sg rule egress": `resource "aws_security_group_rule" "r" {
  type              = "egress"
  from_port         = 22
  to_port           = 22
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-123"
}`,
	}
	for name, src := range cases {
		if fs := onlyRule(findingsFor(t, src), "OPEN-INGRESS"); len(fs) != 0 {
			t.Errorf("%s: findings = %+v, want none", name, fs)
		}
	}
}

func TestOpenIngressRuleResources(t *testing.T) {
	fs := onlyRule(findingsFor(t, `resource "aws_vpc_security_group_ingress_rule" "rdp" {
  cidr_ipv6 = "::/0"
  from_port = 3389
  to_port   = 3389
}
`), "OPEN-INGRESS")
	if len(fs) != 1 || fs[0].Severity != SevCritical {
		t.Fatalf("vpc rule findings = %+v, want one critical (RDP over IPv6)", fs)
	}

	fs = onlyRule(findingsFor(t, `resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = "sg-123"
}
`), "OPEN-INGRESS")
	if len(fs) != 1 || fs[0].Severity != SevCritical {
		t.Fatalf("sg_rule findings = %+v, want one critical", fs)
	}

	// All ports open (0-0) counts as covering SSH.
	fs = onlyRule(findingsFor(t, `resource "aws_security_group" "all" {
  ingress {
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`), "OPEN-INGRESS")
	if len(fs) != 1 || fs[0].Severity != SevCritical {
		t.Fatalf("all-ports findings = %+v, want one critical", fs)
	}
}

// --- PUBLIC-S3 / S3-NO-PUBLIC-ACCESS-BLOCK ----------------------------------

func TestPublicS3(t *testing.T) {
	fs := onlyRule(findingsFor(t, `resource "aws_s3_bucket_acl" "a" {
  bucket = "x"
  acl    = "public-read"
}
`), "PUBLIC-S3")
	if len(fs) != 1 || fs[0].Severity != SevHigh {
		t.Fatalf("bucket_acl findings = %+v, want one high", fs)
	}

	fs = onlyRule(findingsFor(t, `resource "aws_s3_bucket" "b" {
  acl = "public-read-write"
}
`), "PUBLIC-S3")
	if len(fs) != 1 {
		t.Fatalf("inline acl findings = %+v, want one", fs)
	}

	fs = onlyRule(findingsFor(t, `resource "aws_s3_bucket_acl" "a" {
  bucket = "x"
  acl    = "private"
}
`), "PUBLIC-S3")
	if len(fs) != 0 {
		t.Fatalf("private acl findings = %+v, want none", fs)
	}
}

func TestS3PublicAccessBlockCrossFile(t *testing.T) {
	files := map[string]string{
		"a.tf": `resource "aws_s3_bucket" "data" {
  bucket = "company-data"
}
`,
		"b.tf": `resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`,
	}
	p := scanStrings(files, "a.tf", "b.tf")
	if fs := onlyRule(runRules(p), "S3-NO-PUBLIC-ACCESS-BLOCK"); len(fs) != 0 {
		t.Fatalf("cross-file findings = %+v, want none (block is in the other file)", fs)
	}

	// Same bucket, no access block anywhere → one medium finding.
	p = scanStrings(files, "a.tf")
	fs := onlyRule(runRules(p), "S3-NO-PUBLIC-ACCESS-BLOCK")
	if len(fs) != 1 || fs[0].Severity != SevMedium {
		t.Fatalf("unprotected findings = %+v, want one medium", fs)
	}

	// Name-based match: the block names the bucket string.
	files["b.tf"] = `resource "aws_s3_bucket_public_access_block" "data" {
  bucket = "company-data"
}
`
	p = scanStrings(files, "a.tf", "b.tf")
	if fs := onlyRule(runRules(p), "S3-NO-PUBLIC-ACCESS-BLOCK"); len(fs) != 0 {
		t.Fatalf("name-matched findings = %+v, want none", fs)
	}
}

// --- Databases ---------------------------------------------------------------

func TestDatabaseRules(t *testing.T) {
	fs := findingsFor(t, `resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = true
}
`)
	if got := onlyRule(fs, "PUBLIC-DATABASE"); len(got) != 1 || got[0].Severity != SevCritical {
		t.Errorf("PUBLIC-DATABASE = %+v, want one critical", got)
	}
	if got := onlyRule(fs, "UNENCRYPTED-DATABASE"); len(got) != 0 {
		t.Errorf("UNENCRYPTED with encrypted=true = %+v, want none", got)
	}

	fs = findingsFor(t, `resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = false
}
`)
	if got := onlyRule(fs, "PUBLIC-DATABASE"); len(got) != 0 {
		t.Errorf("PUBLIC-DATABASE with false = %+v, want none", got)
	}
	got := onlyRule(fs, "UNENCRYPTED-DATABASE")
	if len(got) != 1 || !strings.Contains(got[0].Message, "is false") {
		t.Errorf("UNENCRYPTED with false = %+v, want one saying it is false", got)
	}

	fs = findingsFor(t, `resource "aws_db_instance" "db" {
  engine = "postgres"
}
`)
	got = onlyRule(fs, "UNENCRYPTED-DATABASE")
	if len(got) != 1 || !strings.Contains(got[0].Message, "not set") {
		t.Errorf("UNENCRYPTED with absent attr = %+v, want one saying it is not set", got)
	}
}

// --- HARDCODED-SECRET --------------------------------------------------------

func TestHardcodedSecretAndMasking(t *testing.T) {
	const secret = "hunter2-do-not-print"
	src := `resource "aws_db_instance" "db" {
  username = "admin"
  password = "` + secret + `"
}

resource "aws_db_instance" "ok" {
  password = var.db_password
}

resource "aws_db_instance" "also_ok" {
  password = "${var.db_password}"
}
`
	fs := onlyRule(findingsFor(t, src), "HARDCODED-SECRET")
	if len(fs) != 1 {
		t.Fatalf("findings = %+v, want exactly one (the literal)", fs)
	}
	if fs[0].Severity != SevCritical || fs[0].Resource != "aws_db_instance.db" {
		t.Errorf("finding = %+v", fs[0])
	}

	// The secret value must never appear in any rendered output.
	rep := Report{Path: ".", FilesScanned: 1, Findings: findingsFor(t, src)}
	if strings.Contains(rep.renderText(), secret) {
		t.Error("secret value leaked into the text report")
	}
	j, err := rep.renderJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(j, secret) {
		t.Error("secret value leaked into the JSON report")
	}
	if !strings.Contains(rep.renderText(), "***") {
		t.Error("report should show the masked placeholder ***")
	}
}

// --- BROAD-IAM ---------------------------------------------------------------

func TestBroadIAMJSONPolicy(t *testing.T) {
	src := `resource "aws_iam_policy" "admin" {
  policy = <<-EOT
    {
      "Statement": [{
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }]
    }
  EOT
}
`
	fs := onlyRule(findingsFor(t, src), "BROAD-IAM")
	if len(fs) != 1 || fs[0].Severity != SevHigh {
		t.Fatalf("findings = %+v, want one high", fs)
	}
}

func TestBroadIAMVariants(t *testing.T) {
	// Service wildcard on all resources fires.
	fs := onlyRule(findingsFor(t, `resource "aws_iam_role_policy" "p" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = "*"
    }]
  })
}
`), "BROAD-IAM")
	if len(fs) != 1 {
		t.Errorf("service wildcard findings = %+v, want one", fs)
	}

	// Broad action but a specific resource: no fire.
	fs = onlyRule(findingsFor(t, `resource "aws_iam_policy" "p" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "arn:aws:s3:::one-bucket/*"
    }]
  })
}
`), "BROAD-IAM")
	if len(fs) != 0 {
		t.Errorf("specific-resource findings = %+v, want none", fs)
	}

	// A Deny is protective, not a grant: no fire.
	fs = onlyRule(findingsFor(t, `resource "aws_iam_policy" "p" {
  policy = <<-EOT
    {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
  EOT
}
`), "BROAD-IAM")
	if len(fs) != 0 {
		t.Errorf("deny findings = %+v, want none", fs)
	}
}

func TestBroadIAMPolicyDocument(t *testing.T) {
	src := `data "aws_iam_policy_document" "doc" {
  statement {
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = ["*"]
  }
}
`
	fs := onlyRule(findingsFor(t, src), "BROAD-IAM")
	if len(fs) != 1 {
		t.Fatalf("policy document findings = %+v, want one", fs)
	}
	if fs[0].Resource != "aws_iam_policy_document.doc" {
		t.Errorf("resource = %q", fs[0].Resource)
	}

	src = `data "aws_iam_policy_document" "doc" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::one-bucket/*"]
  }
}
`
	if fs := onlyRule(findingsFor(t, src), "BROAD-IAM"); len(fs) != 0 {
		t.Errorf("narrow policy document findings = %+v, want none", fs)
	}
}
