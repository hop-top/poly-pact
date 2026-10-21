package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// walker reads data once with json.Decoder tokens, in step with the target
// type, and fails on the first violation.
type walker struct {
	dec      *json.Decoder
	data     []byte
	maxDepth int
	depth    int
	path     []string
}

func walk(data []byte, maxDepth int, target reflect.Type) error {
	w := &walker{dec: json.NewDecoder(bytes.NewReader(data)), data: data, maxDepth: maxDepth}
	w.dec.UseNumber()
	if err := w.value(target); err != nil {
		return err
	}
	if _, err := w.dec.Token(); err != io.EOF {
		return w.fail(ErrTrailingData, "")
	}
	return nil
}

func (w *walker) fail(kind error, format string, args ...any) error {
	var p strings.Builder
	for _, seg := range w.path {
		p.WriteByte('/')
		p.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(seg))
	}
	return &Error{Kind: kind, Path: p.String(), Offset: w.dec.InputOffset(), Detail: fmt.Sprintf(format, args...)}
}

// tokenErr classifies an error from Decoder.Token.
func (w *walker) tokenErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return w.fail(ErrSyntax, "unexpected end of input")
	}
	// A failed Token leaves the offset at the start of the bad value (after
	// white space), so the bad text is what follows.
	off := min(int(w.dec.InputOffset()), len(w.data))
	rest := bytes.TrimLeft(w.data[off:], " \t\r\n")
	for _, lit := range []string{"NaN", "Infinity", "-Infinity", "+Infinity"} {
		if bytes.HasPrefix(rest, []byte(lit)) {
			return w.fail(ErrNonFinite, "%s is not a JSON number", lit)
		}
	}
	return w.fail(ErrSyntax, "%v", err)
}

// resolve reduces target t to what the walk needs: the type to check members
// against (nil when the value is free-form) and whether null is acceptable.
func resolve(t reflect.Type) (typ reflect.Type, nullable bool) {
	if t == nil {
		return nil, true
	}
	nullable = t.Kind() == reflect.Pointer || t.Kind() == reflect.Interface
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Interface || t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil, true
	}
	return t, nullable
}

func (w *walker) value(target reflect.Type) error {
	tok, err := w.dec.Token()
	if err != nil {
		return w.tokenErr(err)
	}
	t, nullable := resolve(target)
	switch v := tok.(type) {
	case json.Delim:
		if v == '{' {
			return w.object(t)
		}
		if v == '[' {
			return w.array(t)
		}
		return w.fail(ErrSyntax, "unexpected %q", rune(v))
	case json.Number:
		return w.number(v, t)
	case nil:
		if !nullable {
			return w.fail(ErrNull, "target %s cannot hold null", target)
		}
	}
	return nil
}

func (w *walker) enter() error {
	w.depth++
	if w.depth > w.maxDepth {
		return w.fail(ErrDepth, "depth %d exceeds the limit of %d", w.depth, w.maxDepth)
	}
	return nil
}

func (w *walker) object(t reflect.Type) error {
	if err := w.enter(); err != nil {
		return err
	}
	var fields map[string]reflect.Type
	var elem reflect.Type
	if t != nil {
		switch t.Kind() {
		case reflect.Struct:
			fields = structFields(t)
		case reflect.Map:
			elem = t.Elem()
		}
	}

	seen := map[string]struct{}{}
	for w.dec.More() {
		tok, err := w.dec.Token()
		if err != nil {
			return w.tokenErr(err)
		}
		key, ok := tok.(string)
		if !ok {
			return w.fail(ErrSyntax, "object member name is not a string")
		}
		w.path = append(w.path, key)
		if _, dup := seen[key]; dup {
			return w.fail(ErrDuplicateKey, "%q", key)
		}
		seen[key] = struct{}{}

		child := elem
		if t != nil && t.Kind() == reflect.Struct {
			ft, known := fields[key]
			if !known {
				return w.fail(ErrUnknownField, "%q is not a field of %s", key, t)
			}
			child = ft
		}
		if err := w.value(child); err != nil {
			return err
		}
		w.path = w.path[:len(w.path)-1]
	}
	if _, err := w.dec.Token(); err != nil { // the closing brace
		return w.tokenErr(err)
	}
	w.depth--
	return nil
}

func (w *walker) array(t reflect.Type) error {
	if err := w.enter(); err != nil {
		return err
	}
	var elem reflect.Type
	if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
		elem = t.Elem()
	}
	for i := 0; w.dec.More(); i++ {
		w.path = append(w.path, strconv.Itoa(i))
		if err := w.value(elem); err != nil {
			return err
		}
		w.path = w.path[:len(w.path)-1]
	}
	if _, err := w.dec.Token(); err != nil { // the closing bracket
		return w.tokenErr(err)
	}
	w.depth--
	return nil
}

func isIntKind(k reflect.Kind) bool {
	return k >= reflect.Int && k <= reflect.Uint64
}

func (w *walker) number(n json.Number, t reflect.Type) error {
	s := string(n)
	intTarget := t != nil && isIntKind(t.Kind())
	if strings.ContainsAny(s, ".eE") {
		if intTarget {
			return w.fail(ErrInteger, "%s is not an integer", s)
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return w.fail(ErrNonFinite, "%s does not fit binary64", s)
		}
		return nil
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil || i > MaxSafeInteger || i < -MaxSafeInteger {
		return w.fail(ErrInteger, "%s is outside ±%d", s, int64(MaxSafeInteger))
	}
	if intTarget && i < 0 {
		return w.fail(ErrInteger, "%s is negative", s)
	}
	return nil
}

var fieldCache sync.Map // reflect.Type -> map[string]reflect.Type

// structFields maps each JSON member name of struct type t to its Go type.
// Embedded structs without a name are flattened, as encoding/json does.
func structFields(t reflect.Type) map[string]reflect.Type {
	if m, ok := fieldCache.Load(t); ok {
		return m.(map[string]reflect.Type)
	}
	m := map[string]reflect.Type{}
	collectFields(t, m)
	fieldCache.Store(t, m)
	return m
}

func collectFields(t reflect.Type, m map[string]reflect.Type) {
	for f := range t.Fields() {
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				collectFields(ft, m)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		if _, taken := m[name]; !taken {
			m[name] = f.Type
		}
	}
}
