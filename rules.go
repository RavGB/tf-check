package main

// The tf-check rules. Each rule is a function over the scanned
// project and returns findings. Rules are deliberately narrow: each
// one fires only on the exact pattern it names, because a first-pass
// scanner that cries wolf gets ignored.

import (
	"fmt"
	"regexp"
	"strings"
)

// runRules runs every rule and returns all findings, unsorted.
func runRules(p *Project) []Finding {
	var out []Finding
	out = append(out, ruleOpenIngress(p)...)
	out = append(out, rulePublicS3(p)...)
	out = append(out, ruleS3NoPublicAccessBlock(p)...)
	out = append(out, rulePublicDatabase(p)...)
	out = append(out, ruleUnencryptedDatabase(p)...)
	out = append(out, ruleHardcodedSecret(p)...)
	out = append(out, ruleBroadIAM(p)...)
	return out
}

// isWorldCIDR reports whether a CIDR string means "any address".
func isWorldCIDR(s string) bool {
	return s == "0.0.0.0/0" || s == "::/0"
}

// openCIDRIn returns the first world-open CIDR named by any of the
// given attributes, or "".
func openCIDRIn(attrs []Attr, names ...string) string {
	for _, name := range names {
		if a, ok := findAttr(attrs, name); ok {
			for _, s := range stringList(a.Raw) {
				if isWorldCIDR(s) {
					return s
				}
			}
			if v, ok := stringValue(a.Raw); ok && isWorldCIDR(v) {
				return v
			}
		}
	}
	return ""
}

// portRange reads from_port/to_port. A missing bound, or 0 to 0,
// means every port (that is what 0-0 means in a security group, and a
// rule that does not limit ports must be treated as unlimited).
func portRange(attrs []Attr) (int, int) {
	from, to := 0, 0
	if a, ok := findAttr(attrs, "from_port"); ok {
		if n, ok2 := intValue(a.Raw); ok2 {
			from = n
		}
	}
	if a, ok := findAttr(attrs, "to_port"); ok {
		if n, ok2 := intValue(a.Raw); ok2 {
			to = n
		}
	}
	return from, to
}

func coversPort(from, to, port int) bool {
	if from == 0 && to == 0 {
		return true
	}
	return from <= port && port <= to
}

// openIngressFinding builds the finding for one open ingress.
func openIngressFinding(p *Project, b Block, line int, cidr string, from, to int) Finding {
	sev := SevHigh
	sensitive := ""
	if coversPort(from, to, 22) {
		sensitive = "SSH (port 22)"
	} else if coversPort(from, to, 3389) {
		sensitive = "Remote Desktop (port 3389)"
	}
	if sensitive != "" {
		sev = SevCritical
	}
	msg := fmt.Sprintf("Ingress allows traffic from any address (%s) to ports %d-%d.", cidr, from, to)
	if sensitive != "" {
		msg += fmt.Sprintf(" That range includes %s, so anyone on the internet can try to connect to it.", sensitive)
	} else {
		msg += " Anyone on the internet can reach these ports."
	}
	return Finding{
		Rule:     "OPEN-INGRESS",
		Severity: sev,
		File:     p.Files[b.File].Path,
		Line:     line,
		Resource: b.Address(),
		Message:  msg,
	}
}

// Rule 1: world-open security group ingress.
func ruleOpenIngress(p *Project) []Finding {
	var out []Finding
	cidrAttrs := []string{"cidr_blocks", "cidr_ipv4", "ipv6_cidr_blocks", "cidr_ipv6"}
	for _, b := range p.Blocks {
		if b.Kind != "resource" {
			continue
		}
		doc := p.Files[b.File]
		switch b.Type {
		case "aws_security_group":
			for _, sub := range subBlocks(doc, b.Start, b.End) {
				if sub.Name != "ingress" {
					continue
				}
				attrs := attributes(doc, sub.Start, sub.End)
				if cidr := openCIDRIn(attrs, cidrAttrs...); cidr != "" {
					from, to := portRange(attrs)
					out = append(out, openIngressFinding(p, b, sub.StartLine, cidr, from, to))
				}
			}
		case "aws_vpc_security_group_ingress_rule":
			attrs := attributes(doc, b.Start, b.End)
			if cidr := openCIDRIn(attrs, cidrAttrs...); cidr != "" {
				from, to := portRange(attrs)
				if proto, ok := findAttr(attrs, "ip_protocol"); ok {
					if v, ok2 := stringValue(proto.Raw); ok2 && v == "-1" {
						from, to = 0, 0 // all protocols and ports
					}
				}
				out = append(out, openIngressFinding(p, b, b.StartLine, cidr, from, to))
			}
		case "aws_security_group_rule":
			attrs := attributes(doc, b.Start, b.End)
			typ, ok := findAttr(attrs, "type")
			if !ok {
				continue
			}
			if v, ok2 := stringValue(typ.Raw); !ok2 || v != "ingress" {
				continue
			}
			if cidr := openCIDRIn(attrs, cidrAttrs...); cidr != "" {
				from, to := portRange(attrs)
				out = append(out, openIngressFinding(p, b, b.StartLine, cidr, from, to))
			}
		}
	}
	return out
}

// Rule 2: a bucket or bucket ACL set to a public canned ACL.
func rulePublicS3(p *Project) []Finding {
	var out []Finding
	for _, b := range p.Blocks {
		if b.Kind != "resource" || (b.Type != "aws_s3_bucket_acl" && b.Type != "aws_s3_bucket") {
			continue
		}
		doc := p.Files[b.File]
		attrs := attributes(doc, b.Start, b.End)
		acl, ok := findAttr(attrs, "acl")
		if !ok {
			continue
		}
		v, isStr := stringValue(acl.Raw)
		if isStr && (v == "public-read" || v == "public-read-write") {
			out = append(out, Finding{
				Rule:     "PUBLIC-S3",
				Severity: SevHigh,
				File:     p.Files[b.File].Path,
				Line:     b.StartLine,
				Resource: b.Address(),
				Message:  fmt.Sprintf("The bucket access control is set to %q, which lets the public read it. Anything in this bucket is open to the internet.", v),
			})
		}
	}
	return out
}

// Rule 3: a bucket with no public access block anywhere in the scan.
func ruleS3NoPublicAccessBlock(p *Project) []Finding {
	// Collect what the public access blocks protect: resource
	// references are matched by address text, name-based buckets by
	// their bucket attribute value.
	protectedRefs := map[string]bool{}
	protectedNames := map[string]bool{}
	for _, b := range p.Blocks {
		if b.Kind != "resource" || b.Type != "aws_s3_bucket_public_access_block" {
			continue
		}
		doc := p.Files[b.File]
		span := doc.Value[b.Start:b.End]
		for _, other := range p.Blocks {
			if other.Type == "aws_s3_bucket" && strings.Contains(span, "aws_s3_bucket."+other.Name) {
				protectedRefs[other.Address()] = true
			}
		}
		if a, ok := findAttr(attributes(doc, b.Start, b.End), "bucket"); ok {
			if v, isStr := stringValue(a.Raw); isStr {
				protectedNames[v] = true
			}
		}
	}

	var out []Finding
	for _, b := range p.Blocks {
		if b.Kind != "resource" || b.Type != "aws_s3_bucket" {
			continue
		}
		if protectedRefs[b.Address()] {
			continue
		}
		doc := p.Files[b.File]
		if a, ok := findAttr(attributes(doc, b.Start, b.End), "bucket"); ok {
			if v, isStr := stringValue(a.Raw); isStr && protectedNames[v] {
				continue
			}
		}
		out = append(out, Finding{
			Rule:     "S3-NO-PUBLIC-ACCESS-BLOCK",
			Severity: SevMedium,
			File:     p.Files[b.File].Path,
			Line:     b.StartLine,
			Resource: b.Address(),
			Message:  "This bucket has no aws_s3_bucket_public_access_block in the scanned files. That block is the safety net that keeps a bucket private even if a policy or ACL is set wrong later.",
		})
	}
	return out
}

// Rule 4: a database instance reachable from the internet.
func rulePublicDatabase(p *Project) []Finding {
	var out []Finding
	for _, b := range p.Blocks {
		if b.Kind != "resource" || b.Type != "aws_db_instance" {
			continue
		}
		doc := p.Files[b.File]
		if a, ok := findAttr(attributes(doc, b.Start, b.End), "publicly_accessible"); ok {
			if v, isBool := boolValue(a.Raw); isBool && v {
				out = append(out, Finding{
					Rule:     "PUBLIC-DATABASE",
					Severity: SevCritical,
					File:     p.Files[b.File].Path,
					Line:     b.StartLine,
					Resource: b.Address(),
					Message:  "publicly_accessible is true, so this database can be reached from the internet. Databases should sit on private subnets and be reached through the application or a bastion.",
				})
			}
		}
	}
	return out
}

// Rule 5: database storage encryption off, or never mentioned.
func ruleUnencryptedDatabase(p *Project) []Finding {
	var out []Finding
	for _, b := range p.Blocks {
		if b.Kind != "resource" || b.Type != "aws_db_instance" {
			continue
		}
		doc := p.Files[b.File]
		a, ok := findAttr(attributes(doc, b.Start, b.End), "storage_encrypted")
		base := Finding{
			Rule:     "UNENCRYPTED-DATABASE",
			Severity: SevMedium,
			File:     p.Files[b.File].Path,
			Line:     b.StartLine,
			Resource: b.Address(),
		}
		if !ok {
			base.Message = "storage_encrypted is not set on this database, so whether its storage is encrypted depends on account defaults. Set it to true to be sure."
			out = append(out, base)
			continue
		}
		if v, isBool := boolValue(a.Raw); isBool && !v {
			base.Message = "storage_encrypted is false, so this database's storage is not encrypted at rest."
			out = append(out, base)
		}
	}
	return out
}

var secretAttrNames = map[string]bool{
	"password":      true,
	"secret":        true,
	"client_secret": true,
	"api_key":       true,
}

// Rule 6: a secret written as a plain string in the code. The value
// itself is never copied into a finding; the message names only the
// attribute, and the raw value is masked wherever a value-like token
// would appear.
func ruleHardcodedSecret(p *Project) []Finding {
	var out []Finding
	for _, b := range p.Blocks {
		doc := p.Files[b.File]
		for _, a := range attributes(doc, b.Start, b.End) {
			if !secretAttrNames[a.Name] {
				continue
			}
			v, isStr := stringValue(a.Raw)
			if !isStr || v == "" {
				continue // a reference or expression, not a literal
			}
			if strings.Contains(v, "${") {
				continue // an interpolation: a reference in string form
			}
			out = append(out, Finding{
				Rule:     "HARDCODED-SECRET",
				Severity: SevCritical,
				File:     p.Files[b.File].Path,
				Line:     a.Line,
				Resource: b.Address(),
				Message:  fmt.Sprintf("Attribute %q is set to a hardcoded value (\"***\") in the code. Anyone who can read this repository knows the secret; move it to a variable fed from a secrets store.", a.Name),
			})
		}
	}
	return out
}

// --- Rule 7 helpers ---------------------------------------------------------

var (
	// "Action": [...] (JSON) and Action = [...] (jsonencode objects,
	// where keys may be quoted or bare) are both recognised.
	jsonActionRe = regexp.MustCompile(`"?Action"?\s*[:=]\s*(\[[^\]]*\]|"[^"]*")`)
	jsonEffectRe = regexp.MustCompile(`"?Effect"?\s*[:=]\s*"Allow"`)
	hclActionsRe = regexp.MustCompile(`\bactions\s*=\s*\[([^\]]*)\]`)
	hclEffectRe  = regexp.MustCompile(`\beffect\s*=\s*"Allow"`)
	svcWildcard  = regexp.MustCompile(`^[a-z0-9]+:\*$`)
)

// broadActionIn looks in a span of text for an allowed-action list
// holding "*" or a whole-service wildcard such as "s3:*", in either
// JSON policy form or the HCL form used by aws_iam_policy_document.
// It returns the offending action, if any.
func broadActionIn(text string) (string, bool) {
	segments := []string{}
	if m := jsonActionRe.FindStringSubmatch(text); m != nil {
		segments = append(segments, m[1])
	}
	if m := hclActionsRe.FindStringSubmatch(text); m != nil {
		segments = append(segments, m[1])
	}
	for _, seg := range segments {
		for _, item := range stringList(seg) {
			if item == "*" || svcWildcard.MatchString(item) {
				return item, true
			}
		}
		if v, ok := stringValue(strings.TrimSpace(seg)); ok && (v == "*" || svcWildcard.MatchString(v)) {
			return v, true
		}
	}
	return "", false
}

// starResourceIn reports whether a span grants on Resource "*".
func starResourceIn(text string) bool {
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`"?Resource"?\s*[:=]\s*(\[[^\]]*\]|"\*")`),
		regexp.MustCompile(`\bresources\s*=\s*\[([^\]]*)\]`),
	} {
		if m := re.FindStringSubmatch(text); m != nil {
			for _, item := range stringList(m[1]) {
				if item == "*" {
					return true
				}
			}
			if strings.TrimSpace(m[1]) == `"*"` {
				return true
			}
		}
	}
	return false
}

func allowEffectIn(text string) bool {
	return jsonEffectRe.MatchString(text) || hclEffectRe.MatchString(text)
}

// Rule 7: an IAM policy that allows a broad action on every resource.
// This is a targeted text check on the policy block's span, not a
// JSON evaluation: it requires an Allow effect, a broad action, and
// Resource "*" to all appear in the same policy (for
// aws_iam_policy_document, in the same statement block).
func ruleBroadIAM(p *Project) []Finding {
	var out []Finding
	fire := func(p *Project, b Block, action string) Finding {
		return Finding{
			Rule:     "BROAD-IAM",
			Severity: SevHigh,
			File:     p.Files[b.File].Path,
			Line:     b.StartLine,
			Resource: b.Address(),
			Message:  fmt.Sprintf("This policy allows %q on every resource (\"Resource\": \"*\"). If these credentials leak, that is access to everything the action touches; narrow the action and the resources to what is actually needed.", action),
		}
	}
	for _, b := range p.Blocks {
		doc := p.Files[b.File]
		span := doc.Value[b.Start:b.End]
		switch {
		case b.Kind == "resource" && (b.Type == "aws_iam_policy" || b.Type == "aws_iam_role_policy"):
			if action, ok := broadActionIn(span); ok && starResourceIn(span) && allowEffectIn(span) {
				out = append(out, fire(p, b, action))
			}
		case b.Kind == "data" && b.Type == "aws_iam_policy_document":
			for _, sub := range subBlocks(doc, b.Start, b.End) {
				if sub.Name != "statement" {
					continue
				}
				subSpan := doc.Value[sub.Start:sub.End]
				if action, ok := broadActionIn(subSpan); ok && starResourceIn(subSpan) && allowEffectIn(subSpan) {
					f := fire(p, b, action)
					f.Line = sub.StartLine
					out = append(out, f)
				}
			}
		}
	}
	return out
}
