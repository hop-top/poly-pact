package main

import (
	"regexp"
	"sort"
	"strings"
)

// The link extractor recognizes the CommonMark subset that
// scripts/check-spec-selfcontained.py recognizes, with the same rules: inline
// links and images [t](dest "title"), angle-bracket destinations
// [t](<dest>), reference definitions [ref]: dest, and the href and src
// attributes of inline HTML. Not links: anything inside a fenced code block,
// a code span or an HTML comment. Reference uses ([t][ref]) need no handling
// because their destination is the definition. Indented code blocks are not
// recognized, so a link written in one is still checked.

var (
	fenceOpenRE  = regexp.MustCompile("^[ \t>]*(?:(?:[-*+]|[0-9]{1,9}[.)])[ \t]+)?(`{3,}|~{3,})(.*)$")
	fenceCloseRE = regexp.MustCompile("^[ \t>]*(`{3,}|~{3,})[ \t]*$")
	ticksRE      = regexp.MustCompile("^`+")
	anyTicksRE   = regexp.MustCompile("`+")
	blankLineRE  = regexp.MustCompile("^[ \t]*(?:\n|$)")
	blankRunRE   = regexp.MustCompile("\n[ \t]*\n")
	tableLineRE  = regexp.MustCompile(`(?m)^[ \t]*\|.*$`)
	definitionRE = regexp.MustCompile(`^\[(?:[^\]\\\n]|\\.)+\]:[ \t]*\n?[ \t]*(<[^<>\n]*>|[^\s<]\S*)`)
	htmlTagRE    = regexp.MustCompile(`^<[A-Za-z][^<>]*>`)
	htmlURLRE    = regexp.MustCompile("(?i)\\b(?:href|src)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'=<>`]+))")
)

// link is one link destination as written, with its 1-based line.
type link struct {
	line int
	dest string
}

// blankFences empties every line of a fenced code block, fences included.
func blankFences(lines []string) []string {
	out := make([]string, 0, len(lines))
	fence := ""
	for _, line := range lines {
		if fence == "" {
			m := fenceOpenRE.FindStringSubmatch(line)
			// A backtick fence cannot carry a backtick in its info string:
			// that line is an inline code span.
			if m != nil && (m[1][0] != '`' || !strings.Contains(m[2], "`")) {
				fence = m[1]
			} else {
				out = append(out, line)
				continue
			}
		} else if m := fenceCloseRE.FindStringSubmatch(line); m != nil && m[1][0] == fence[0] && len(m[1]) >= len(fence) {
			fence = ""
		}
		out = append(out, "")
	}
	return out
}

// boundaries are the offsets a code span cannot cross: blank lines and the
// edges of table rows.
func boundaries(text string) []int {
	var b []int
	for _, m := range blankRunRE.FindAllStringIndex(text, -1) {
		b = append(b, m[0])
	}
	for _, m := range tableLineRE.FindAllStringIndex(text, -1) {
		b = append(b, m[0], m[1])
	}
	sort.Ints(b)
	return b
}

// skipWS skips spaces, tabs and at most one line ending.
func skipWS(text string, i int) int {
	newline := false
	for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' && !newline) {
		newline = newline || text[i] == '\n'
		i++
	}
	return i
}

// parseInlineDest parses `dest "title")` after `](`; ok is false when the
// text there is not a link destination.
func parseInlineDest(text string, i int) (dest string, end int, ok bool) {
	n := len(text)
	i = skipWS(text, i)
	var j int
	if i < n && text[i] == '<' {
		j = i + 1
		for j < n && text[j] != '>' {
			if text[j] == '\n' || text[j] == '<' {
				return "", 0, false
			}
			if text[j] == '\\' {
				j += 2
			} else {
				j++
			}
		}
		if j >= n {
			return "", 0, false
		}
		dest = text[i+1 : j]
		j++
	} else {
		depth := 0
		j = i
		for j < n && text[j] != ' ' && text[j] != '\t' && text[j] != '\n' && text[j] >= 0x20 {
			if text[j] == '\\' && j+1 < n {
				j += 2
				continue
			}
			if text[j] == '(' {
				depth++
			} else if text[j] == ')' {
				if depth == 0 {
					break
				}
				depth--
			}
			j++
		}
		if depth != 0 {
			return "", 0, false
		}
		dest = text[i:j]
	}
	k := skipWS(text, j)
	if k > j && k < n && strings.IndexByte(`"'(`, text[k]) >= 0 {
		closer := text[k]
		if closer == '(' {
			closer = ')'
		}
		m := k + 1
		for m < n && text[m] != closer {
			if text[m] == '\\' {
				m += 2
			} else {
				m++
			}
		}
		if m >= n {
			return "", 0, false
		}
		k = skipWS(text, m+1)
	}
	if k < n && text[k] == ')' {
		return dest, k + 1, true
	}
	return "", 0, false
}

// extractLinks returns every link destination outside code, as written.
func extractLinks(text string) []link {
	text = strings.Join(blankFences(strings.Split(text, "\n")), "\n")
	n := len(text)
	bounds := boundaries(text)
	var newlines []int
	for i := 0; i < n; i++ {
		if text[i] == '\n' {
			newlines = append(newlines, i)
		}
	}
	lineOf := func(off int) int {
		return sort.Search(len(newlines), func(k int) bool { return newlines[k] > off }) + 1
	}
	var found []link
	var stack []int // open [ of the current paragraph
	for i := 0; i < n; {
		c := text[i]
		switch {
		case c == '\\':
			i += 2
		case c == '`':
			run := ticksRE.FindString(text[i:])
			end := i + len(run)
			k := sort.SearchInts(bounds, end)
			limit := n
			if k < len(bounds) {
				limit = bounds[k]
			}
			next := end
			if limit > end {
				for _, m := range anyTicksRE.FindAllStringIndex(text[end:limit], -1) {
					if m[1]-m[0] == len(run) {
						next = end + m[1]
						break
					}
				}
			}
			i = next
		case strings.HasPrefix(text[i:], "<!--"):
			if e := strings.Index(text[i+4:], "-->"); e < 0 {
				i += 4
			} else {
				i += 4 + e + 3
			}
		case c == '<':
			tag := htmlTagRE.FindString(text[i:])
			if tag == "" {
				i++
				break
			}
			for _, a := range htmlURLRE.FindAllStringSubmatch(tag, -1) {
				found = append(found, link{lineOf(i), a[1] + a[2] + a[3]})
			}
			i += len(tag)
		case c == '[':
			start := strings.LastIndexByte(text[:i], '\n') + 1
			var def []int
			if i-start <= 3 && strings.Trim(text[start:i], " ") == "" && !strings.HasPrefix(text[i:], "[^") {
				def = definitionRE.FindStringSubmatchIndex(text[i:])
			}
			if def == nil {
				stack = append(stack, i)
				i++
				break
			}
			dest := text[i+def[2] : i+def[3]]
			if strings.HasPrefix(dest, "<") {
				dest = dest[1 : len(dest)-1]
			}
			found = append(found, link{lineOf(i), dest})
			i += def[1]
		case c == ']':
			ok := false
			var dest string
			var end int
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
				if strings.HasPrefix(text[i+1:], "(") {
					dest, end, ok = parseInlineDest(text, i+2)
				}
			}
			if ok {
				found = append(found, link{lineOf(i), dest})
				i = end
			} else {
				i++
			}
		case c == '\n':
			if blankLineRE.MatchString(text[i+1:]) {
				stack = stack[:0]
			}
			i++
		default:
			i++
		}
	}
	return found
}
