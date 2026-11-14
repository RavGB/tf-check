package main

// This file holds the lightweight Terraform scanner.
//
// tf-check deliberately does NOT parse HCL. It reads .tf files as text
// and extracts just enough structure to run its rules: top-level
// resource and data blocks, the sub-blocks directly inside them, and
// name = value attributes. It never evaluates expressions, variables,
// or functions. That limitation is stated in the README, and the rules
// are written to tolerate what this scanner cannot see.
//
// The core technique is two parallel copies of each file, both exactly
// the same length as the original (characters are replaced with
// spaces, newlines are kept), so every offset and line number is true
// in both:
//
//   - structure text: comments blanked, string contents blanked, and
//     heredoc bodies blanked. Braces in this text are always real
//     block braces, never braces inside a string, a comment, or a
//     JSON document embedded in a heredoc, so brace matching runs on
//     this text.
//   - value text: only comments blanked. Attribute values, labels,
//     and embedded JSON are read from this text.
//
// Attribute reads within a span see attributes at any nesting level
// of that span: an attribute inside a nested sub-block is reported as
// part of the enclosing block too. This bleed is deliberate (rules
// like "is there a storage_encrypted anywhere in this resource" want
// it), and rules that must not bleed read a sub-block's own span
// instead.

import (
	"regexp"
	"strings"
)

// FileDoc is one .tf file in its two parallel forms.
type FileDoc struct {
	Path      string // path as walked, shown in findings
	Value     string // comments blanked; strings and heredocs intact
	Structure string // comments, string contents, heredoc bodies blanked
}

// Block is a top-level resource or data block.
type Block struct {
	Kind      string // "resource" or "data"
	Type      string // e.g. aws_db_instance
	Name      string // the second label
	File      int    // index into the project's file list
	StartLine int    // 1-based line of the block header
	Start     int    // offset of the header in the file texts
	End       int    // offset just past the closing brace
}

// Address returns the Terraform address, e.g. aws_db_instance.main.
func (b Block) Address() string { return b.Type + "." + b.Name }

// SubBlock is a block directly inside another block's span.
type SubBlock struct {
	Name      string
	StartLine int
	Start     int
	End       int
}

// Attr is one name = value assignment found in a span.
type Attr struct {
	Name  string
	Raw   string // the value text exactly as written (trimmed)
	Line  int    // 1-based line of the attribute name
	Start int    // offset of the attribute name
}

// Project is everything scanned: files plus their top-level blocks.
type Project struct {
	Files  []FileDoc
	Blocks []Block
}

// ---------------------------------------------------------------------------
// Text transformation
// ---------------------------------------------------------------------------

// transform returns a copy of src with comments blanked. When
// blankStrings is true, string contents and heredoc bodies are
// blanked too (the structure text); otherwise they are preserved
// (the value text). Blanked characters become spaces; newlines are
// never touched, so offsets and line numbers are unchanged.
func transform(src string, blankStrings bool) string {
	out := []byte(src)
	blank := func(i int) {
		if out[i] != '\n' {
			out[i] = ' '
		}
	}

	const (
		stNormal = iota
		stString
		stLineComment
		stBlockComment
	)
	state := stNormal
	heredoc := "" // marker while inside a heredoc body, "" otherwise

	i := 0
	for i < len(src) {
		// Heredoc bodies are whole lines: handle them at line starts
		// before any other state work. A line whose trimmed content is
		// the marker ends the heredoc and is itself normal code.
		if heredoc != "" && state == stNormal && (i == 0 || src[i-1] == '\n') {
			lineEnd := strings.IndexByte(src[i:], '\n')
			var line string
			if lineEnd < 0 {
				line = src[i:]
			} else {
				line = src[i : i+lineEnd]
			}
			if strings.TrimSpace(line) == heredoc {
				heredoc = ""
			} else {
				if blankStrings {
					for j := i; j < i+len(line); j++ {
						blank(j)
					}
				}
				i += len(line)
				continue
			}
		}

		c := src[i]
		switch state {
		case stNormal:
			switch {
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				blank(i)
				blank(i + 1)
				i += 2
				state = stLineComment
			case c == '#':
				blank(i)
				i++
				state = stLineComment
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				blank(i)
				blank(i + 1)
				i += 2
				state = stBlockComment
			case c == '"':
				if blankStrings {
					blank(i)
				}
				i++
				state = stString
			case c == '<' && i+1 < len(src) && src[i+1] == '<':
				// Possible heredoc start: <<MARKER or <<-MARKER.
				j := i + 2
				if j < len(src) && src[j] == '-' {
					j++
				}
				k := j
				for k < len(src) && (src[k] == '_' || src[k] >= '0' && src[k] <= '9' || src[k] >= 'a' && src[k] <= 'z' || src[k] >= 'A' && src[k] <= 'Z') {
					k++
				}
				if k > j && !(src[j] >= '0' && src[j] <= '9') {
					heredoc = src[j:k]
					i = k
				} else {
					i++
				}
			default:
				i++
			}
		case stString:
			if blankStrings {
				blank(i)
			}
			switch c {
			case '\\':
				if i+1 < len(src) {
					if blankStrings {
						blank(i + 1)
					}
					i += 2
				} else {
					i++
				}
			case '"':
				i++
				state = stNormal
			case '\n':
				// Unterminated string: HCL quoted strings do not span
				// lines, so bail out instead of eating the file.
				i++
				state = stNormal
			default:
				i++
			}
		case stLineComment:
			if c == '\n' {
				state = stNormal
				i++
			} else {
				blank(i)
				i++
			}
		case stBlockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				blank(i)
				blank(i + 1)
				i += 2
				state = stNormal
			} else {
				blank(i)
				i++
			}
		}
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// Block and attribute extraction
// ---------------------------------------------------------------------------

var headerRe = regexp.MustCompile(`\b(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{`)

// matchBrace returns the offset of the closing brace that matches the
// opening brace at offset open in the structure text, or -1. Only the
// structure text may be used: its braces are all real.
func matchBrace(structure string, open int) int {
	depth := 0
	for i := open; i < len(structure); i++ {
		switch structure[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// lineOf converts a byte offset to a 1-based line number.
func lineOf(text string, offset int) int {
	if offset > len(text) {
		offset = len(text)
	}
	return strings.Count(text[:offset], "\n") + 1
}

// parseFile builds a FileDoc and extracts its top-level blocks.
func parseFile(path string, src string, fileIndex int) (FileDoc, []Block) {
	doc := FileDoc{
		Path:      path,
		Value:     transform(src, false),
		Structure: transform(src, true),
	}
	var blocks []Block
	pos := 0
	for pos < len(doc.Value) {
		m := headerRe.FindStringSubmatchIndex(doc.Value[pos:])
		if m == nil {
			break
		}
		start := pos + m[0]
		openBrace := pos + m[1] - 1 // the header match ends with '{'
		end := matchBrace(doc.Structure, openBrace)
		if end < 0 {
			end = len(doc.Value) - 1 // unterminated block: take the rest
		}
		blocks = append(blocks, Block{
			Kind:      doc.Value[pos+m[2] : pos+m[3]],
			Type:      doc.Value[pos+m[4] : pos+m[5]],
			Name:      doc.Value[pos+m[6] : pos+m[7]],
			File:      fileIndex,
			StartLine: lineOf(doc.Value, start),
			Start:     start,
			End:       end + 1,
		})
		pos = end + 1
	}
	return doc, blocks
}

var subBlockRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_-]*)\s*\{`)

// subBlocks finds the blocks directly inside the span [start, end) of
// a document: a word followed by '{', where the brace is not an
// attribute value (those are preceded by '=' and never match, because
// the word and the brace must be adjacent but for whitespace).
// Scanning skips over each found sub-block, so only one level is
// returned.
func subBlocks(doc FileDoc, start, end int) []SubBlock {
	var subs []SubBlock
	if end > len(doc.Value) {
		end = len(doc.Value)
	}
	pos := start
	for pos < end {
		m := subBlockRe.FindStringSubmatchIndex(doc.Value[pos:end])
		if m == nil {
			break
		}
		subStart := pos + m[0]
		openBrace := pos + m[1] - 1
		subEnd := matchBrace(doc.Structure, openBrace)
		if subEnd < 0 || subEnd >= end {
			// Not a well-formed sub-block inside this span; move past
			// the match and keep looking.
			pos = pos + m[1]
			continue
		}
		subs = append(subs, SubBlock{
			Name:      doc.Value[pos+m[2] : pos+m[3]],
			StartLine: lineOf(doc.Value, subStart),
			Start:     subStart,
			End:       subEnd + 1,
		})
		pos = subEnd + 1
	}
	return subs
}

var attrRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*=\s*`)

// attributes returns every name = value assignment in the span,
// including those inside nested sub-blocks (see the file comment).
// Values are captured from the value text: quoted strings whole,
// lists and maps by balanced brackets (counted on the structure
// text), and anything else to the end of the line.
func attributes(doc FileDoc, start, end int) []Attr {
	var attrs []Attr
	if end > len(doc.Value) {
		end = len(doc.Value)
	}
	pos := start
	for pos < end {
		m := attrRe.FindStringSubmatchIndex(doc.Value[pos:end])
		if m == nil {
			break
		}
		nameStart := pos + m[0]
		valStart := pos + m[1]
		valEnd := captureValue(doc, valStart, end)
		attrs = append(attrs, Attr{
			Name:  doc.Value[pos+m[2] : pos+m[3]],
			Raw:   strings.TrimSpace(doc.Value[valStart:valEnd]),
			Line:  lineOf(doc.Value, nameStart),
			Start: nameStart,
		})
		if valEnd <= valStart {
			valEnd = valStart + 1
		}
		pos = valEnd
	}
	return attrs
}

// captureValue returns the offset just past the value that starts at
// offset start, never going past limit.
func captureValue(doc FileDoc, start, limit int) int {
	if start >= limit || start >= len(doc.Value) {
		return start
	}
	switch doc.Value[start] {
	case '"':
		// Quoted string: scan to the closing quote, honouring escapes.
		for i := start + 1; i < limit; i++ {
			switch doc.Value[i] {
			case '\\':
				i++
			case '"':
				return i + 1
			case '\n':
				return i
			}
		}
		return limit
	case '[', '{':
		// Balanced brackets, counted on the structure text so that
		// brackets inside strings do not count.
		depth := 0
		for i := start; i < limit; i++ {
			switch doc.Structure[i] {
			case '[', '{':
				depth++
			case ']', '}':
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
		return limit
	default:
		// Scalar or expression: to the end of the line.
		if nl := strings.IndexByte(doc.Value[start:limit], '\n'); nl >= 0 {
			return start + nl
		}
		return limit
	}
}

// ---------------------------------------------------------------------------
// Attribute value helpers
// ---------------------------------------------------------------------------

// findAttr returns the first attribute with the given name, if any.
func findAttr(attrs []Attr, name string) (Attr, bool) {
	for _, a := range attrs {
		if a.Name == name {
			return a, true
		}
	}
	return Attr{}, false
}

// stringValue returns the contents of a quoted-string raw value.
// The second result is false when the raw value is not a quoted
// string.
func stringValue(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		return raw[1 : len(raw)-1], true
	}
	return "", false
}

// stringList returns every quoted string inside a raw value (a single
// string counts as a one-item list).
func stringList(raw string) []string {
	var out []string
	rest := raw
	for {
		i := strings.IndexByte(rest, '"')
		if i < 0 {
			return out
		}
		// Find the closing quote, honouring escapes.
		j := i + 1
		for j < len(rest) && rest[j] != '"' {
			if rest[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(rest) {
			return out
		}
		out = append(out, rest[i+1:j])
		rest = rest[j+1:]
	}
}

// intValue parses a raw scalar as an integer.
func intValue(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	neg := false
	if strings.HasPrefix(raw, "-") {
		neg = true
		raw = raw[1:]
	}
	if raw == "" {
		return 0, false
	}
	n := 0
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}

// boolValue reports (true, true) for = true, (false, true) for
// = false, and (_, false) for anything else.
func boolValue(raw string) (bool, bool) {
	switch strings.TrimSpace(raw) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}
