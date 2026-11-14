package main

import (
	"strings"
	"testing"
)

func parseOne(t *testing.T, src string) (FileDoc, []Block) {
	t.Helper()
	doc, blocks := parseFile("test.tf", src, 0)
	return doc, blocks
}

func TestTransformPreservesOffsetsAndNewlines(t *testing.T) {
	src := "a = \"x { y }\" # comment }\n/* multi\nline } */\nb = 2\n"
	for _, blankStrings := range []bool{true, false} {
		out := transform(src, blankStrings)
		if len(out) != len(src) {
			t.Fatalf("blankStrings=%v: length changed: %d != %d", blankStrings, len(out), len(src))
		}
		for i := 0; i < len(src); i++ {
			if (src[i] == '\n') != (out[i] == '\n') {
				t.Fatalf("blankStrings=%v: newline moved at offset %d", blankStrings, i)
			}
		}
		if strings.Contains(out, "comment") || strings.Contains(out, "multi") {
			t.Errorf("blankStrings=%v: comment text survived: %q", blankStrings, out)
		}
	}
	if got := transform(src, true); strings.Contains(got, "x { y }") {
		t.Errorf("structure text kept string contents: %q", got)
	}
	if got := transform(src, false); !strings.Contains(got, "x { y }") {
		t.Errorf("value text lost string contents: %q", got)
	}
}

func TestBlockExtractionIgnoresBracesInStringsAndComments(t *testing.T) {
	src := `resource "aws_s3_bucket" "a" {
  # a comment with } and { braces
  description = "braces { } and a \"quote\" inside"
  /* block comment } { */
}

resource "aws_s3_bucket" "b" {
}
`
	_, blocks := parseOne(t, src)
	if len(blocks) != 2 {
		t.Fatalf("blocks = %d, want 2", len(blocks))
	}
	if blocks[0].Name != "a" || blocks[1].Name != "b" {
		t.Errorf("names = %q, %q; want a, b", blocks[0].Name, blocks[1].Name)
	}
	if blocks[1].StartLine != 7 {
		t.Errorf("second block line = %d, want 7", blocks[1].StartLine)
	}
}

func TestBlockExtractionWithHeredocJSON(t *testing.T) {
	src := `resource "aws_iam_policy" "p" {
  policy = <<-EOT
    {"Statement": [{"Action": "*", "Resource": "*"}]}
  EOT
}

resource "aws_s3_bucket" "after" {
}
`
	_, blocks := parseOne(t, src)
	if len(blocks) != 2 {
		t.Fatalf("blocks = %d, want 2 (heredoc braces must not break matching)", len(blocks))
	}
	if blocks[1].Name != "after" {
		t.Errorf("second block = %q, want after", blocks[1].Name)
	}
}

func TestNestedSubBlocks(t *testing.T) {
	src := `resource "aws_security_group" "web" {
  ingress {
    from_port = 22
  }
  egress {
    from_port = 0
  }
  tags = {
    Name = "web"
  }
}
`
	doc, blocks := parseOne(t, src)
	if len(blocks) != 1 {
		t.Fatalf("blocks = %d, want 1", len(blocks))
	}
	subs := subBlocks(doc, blocks[0].Start, blocks[0].End)
	if len(subs) != 2 {
		t.Fatalf("sub-blocks = %d, want 2 (ingress, egress; the tags map is not a block)", len(subs))
	}
	if subs[0].Name != "ingress" || subs[0].StartLine != 2 {
		t.Errorf("first sub = %+v, want ingress at line 2", subs[0])
	}
	if subs[1].Name != "egress" {
		t.Errorf("second sub = %q, want egress", subs[1].Name)
	}
}

func TestCRLFLineNumbers(t *testing.T) {
	src := "resource \"aws_db_instance\" \"db\" {\r\n  publicly_accessible = true\r\n}\r\n"
	_, blocks := parseOne(t, src)
	if len(blocks) != 1 {
		t.Fatalf("blocks = %d, want 1", len(blocks))
	}
	doc, _ := parseOne(t, src)
	attrs := attributes(doc, blocks[0].Start, blocks[0].End)
	a, ok := findAttr(attrs, "publicly_accessible")
	if !ok {
		t.Fatal("publicly_accessible not found in CRLF file")
	}
	if a.Line != 2 {
		t.Errorf("attr line = %d, want 2", a.Line)
	}
	if v, isBool := boolValue(a.Raw); !isBool || !v {
		t.Errorf("boolValue(%q) = %v,%v; want true,true (trailing CR must not matter)", a.Raw, v, isBool)
	}
}

func TestAttributeCaptureForms(t *testing.T) {
	src := `resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0", "10.0.0.0/8"]
    from_port   = 22
    self        = true
  }
}
`
	doc, blocks := parseOne(t, src)
	subs := subBlocks(doc, blocks[0].Start, blocks[0].End)
	attrs := attributes(doc, subs[0].Start, subs[0].End)
	cidr, ok := findAttr(attrs, "cidr_blocks")
	if !ok {
		t.Fatal("cidr_blocks not found")
	}
	got := stringList(cidr.Raw)
	if len(got) != 2 || got[0] != "0.0.0.0/0" || got[1] != "10.0.0.0/8" {
		t.Errorf("cidr_blocks strings = %v", got)
	}
	fp, _ := findAttr(attrs, "from_port")
	if n, ok := intValue(fp.Raw); !ok || n != 22 {
		t.Errorf("from_port = %q → %d,%v; want 22,true", fp.Raw, n, ok)
	}
}
