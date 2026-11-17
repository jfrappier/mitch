package findings

import (
	"strings"
)

// pattern is a policy path, prepared for matching the way Vault matches it.
// Vault has three kinds of path rules (vault/policy.go, normalizePath, and
// vault/acl.go):
//
//   - exact: no wildcards, for example "secret/data/app"
//   - prefix: ends in "*" and has no "+", for example "secret/data/*"
//   - segment wildcard: has a "+" segment, for example "secret/+/app/*"
//
// Source: https://github.com/hashicorp/vault/blob/main/vault/acl.go
type pattern struct {
	raw string
	// isExact, isPrefix and hasSegmentWildcards: exactly one kind applies,
	// except that a segment-wildcard path can also end in "*".
	isExact             bool
	isPrefix            bool
	hasSegmentWildcards bool
	// literal is the path with a trailing "*" removed.
	literal string
}

// templateMarker starts an identity template such as {{identity.entity.id}}.
// Mitch cannot know the value, so a segment holding a template matches any
// one segment, like "+".
const templateMarker = "{{"

// newPattern prepares a policy path for matching.
func newPattern(raw string) pattern {
	prepared := pattern{raw: raw, literal: raw}

	// Same test as Vault's normalizePath, plus templated segments.
	prepared.hasSegmentWildcards = raw == "+" ||
		strings.Contains(raw, "/+") ||
		strings.HasPrefix(raw, "+/") ||
		strings.Contains(raw, templateMarker)

	if strings.HasSuffix(raw, "*") {
		prepared.literal = strings.TrimSuffix(raw, "*")
		prepared.isPrefix = true
	}
	prepared.isExact = !prepared.isPrefix && !prepared.hasSegmentWildcards
	return prepared
}

// matches reports whether the pattern applies to a request path.
func (p pattern) matches(path string) bool {
	if p.isExact {
		return p.raw == path
	}
	if !p.hasSegmentWildcards {
		return strings.HasPrefix(path, p.literal)
	}
	_, matched := p.matchSegments(path)
	return matched
}

// matchSegments matches a segment-wildcard pattern against a path, segment
// by segment, as Vault's tryMatchWildcardPath does. It returns how many "+"
// segments it used.
func (p pattern) matchSegments(path string) (int, bool) {
	patternParts := strings.Split(p.literal, "/")
	pathParts := strings.Split(path, "/")
	if len(pathParts) < len(patternParts) {
		return 0, false
	}
	if !p.isPrefix && len(pathParts) != len(patternParts) {
		return 0, false
	}

	wildcards := 0
	for index, patternPart := range patternParts {
		isLast := index == len(patternParts)-1
		switch {
		case patternPart == "+" || strings.Contains(patternPart, templateMarker):
			wildcards++
		case patternPart == pathParts[index]:
			// Same literal segment.
		case p.isPrefix && isLast && strings.HasPrefix(pathParts[index], patternPart):
			// The trailing "*" covers the rest of this segment and beyond.
		default:
			return 0, false
		}
	}
	return wildcards, true
}

// priority describes how specific a matching rule is, using the fields Vault
// ranks by (wcPathDescr in vault/acl.go).
type priority struct {
	isExact       bool
	firstWildcard int
	isPrefix      bool
	wildcards     int
	literal       string
}

// priorityFor returns the priority of p when it matches path. Call it only
// when p.matches(path) is true.
func (p pattern) priorityFor(path string) priority {
	if p.isExact {
		return priority{isExact: true, literal: p.raw}
	}
	if !p.hasSegmentWildcards {
		return priority{firstWildcard: len(p.literal), isPrefix: true, literal: p.literal}
	}
	wildcards, _ := p.matchSegments(path)
	return priority{
		firstWildcard: firstWildcardIndex(p.raw),
		isPrefix:      p.isPrefix,
		wildcards:     wildcards,
		literal:       p.literal,
	}
}

// firstWildcardIndex is the position of the first "+" (or template), as
// Vault's strings.Index(path, "+").
func firstWildcardIndex(raw string) int {
	plus := strings.Index(raw, "+")
	template := strings.Index(raw, templateMarker)
	switch {
	case plus < 0:
		return template
	case template < 0:
		return plus
	case template < plus:
		return template
	default:
		return plus
	}
}

// beats reports whether a rule with priority a wins over one with priority b
// for the same request path. An exact match always wins; otherwise this is
// Vault's wildcardPathDescriptorComparePriority, which ranks by:
//
//  1. the later first wildcard or glob wins
//  2. a rule without a trailing "*" wins over one with it
//  3. fewer "+" segments win
//  4. the longer path wins
//  5. the lexicographically larger path wins
//
// Docs: https://developer.hashicorp.com/vault/docs/concepts/policies#priority-matching
func (a priority) beats(b priority) bool {
	if a.isExact != b.isExact {
		return a.isExact
	}
	if a.firstWildcard != b.firstWildcard {
		return a.firstWildcard > b.firstWildcard
	}
	if a.isPrefix != b.isPrefix {
		return !a.isPrefix
	}
	if a.wildcards != b.wildcards {
		return a.wildcards < b.wildcards
	}
	if len(a.literal) != len(b.literal) {
		return len(a.literal) > len(b.literal)
	}
	return a.literal > b.literal
}

// probePath is a sample request path the pattern matches: every "+" or
// template becomes a placeholder segment, and a trailing "*" gets a
// placeholder appended. Rules use it to ask "does this other rule also apply
// to some path this rule covers?"
func (p pattern) probePath() string {
	parts := strings.Split(p.literal, "/")
	for index, part := range parts {
		if part == "+" || strings.Contains(part, templateMarker) {
			parts[index] = probeSegment
		}
	}
	path := strings.Join(parts, "/")
	if p.isPrefix {
		path = path + probeSegment
	}
	return path
}

// probeSegment is a path segment no real Vault path is expected to use.
const probeSegment = "mitch-probe"
