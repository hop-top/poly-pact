package runner

import "strings"

// BuildArgv splits the argv template tmpl on white space and replaces each
// {name} in an argument by subs[name]. No shell is involved: the first field
// is the executable and the others are literal arguments. Values are
// substituted after the split and in one pass, so a value stays one argument
// and a token inside a value is not replaced again. A token without a value
// in subs is left as it is. A blank template yields nil.
func BuildArgv(tmpl string, subs map[string]string) []string {
	fields := strings.Fields(tmpl)
	if len(fields) == 0 {
		return nil
	}
	pairs := make([]string, 0, 2*len(subs))
	for k, v := range subs {
		pairs = append(pairs, "{"+k+"}", v)
	}
	r := strings.NewReplacer(pairs...)
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = r.Replace(f)
	}
	return out
}
