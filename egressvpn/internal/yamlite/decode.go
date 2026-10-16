package yamlite

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Unmarshal parses data and fills out, which must be a pointer to a struct whose
// fields carry `yaml:"name"` tags. Keys absent from the document leave the field
// at its zero value, which is how applyDefaults tells "unset" from "set to 0";
// keys present but unknown are an error.
func Unmarshal(data []byte, out any) error {
	node, err := Parse(data)
	if err != nil {
		return err
	}
	if node.Kind != Mapping {
		return fmt.Errorf("line %d: config must be a mapping at the top level", node.Line)
	}
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return fmt.Errorf("out must be a non-nil pointer, got %T", out)
	}
	return decode("", node, v.Elem())
}

func decode(path string, n *Node, v reflect.Value) error {
	where := path
	if where == "" {
		where = "config"
	}
	// an empty value means "not specified", not "zero of the wrong type"
	if n.Kind == Scalar && n.Str == "" && v.Kind() != reflect.String {
		return nil
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		return decode(path, n, v.Elem())
	case reflect.Struct:
		return decodeStruct(where, n, v)
	case reflect.Slice:
		return decodeSlice(where, n, v)
	case reflect.String:
		if n.Kind != Scalar {
			return fmt.Errorf("%s: want a single value, got a %s (line %d)", where, kindName(n.Kind), n.Line)
		}
		v.SetString(n.Str)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := strconv.Atoi(n.Str)
		if err != nil {
			return fmt.Errorf("%s: want a whole number, got %q (line %d)", where, n.Str, n.Line)
		}
		v.SetInt(int64(i))
	case reflect.Bool:
		switch n.Str {
		case "true":
			v.SetBool(true)
		case "false":
			v.SetBool(false)
		default:
			// y/yes/on are YAML 1.1 booleans; accepting them would make an unquoted
			// string like "no" ambiguous with the field's intent
			return fmt.Errorf("%s: want true or false, got %q (line %d)", where, n.Str, n.Line)
		}
	default:
		return fmt.Errorf("%s: unsupported field type %s", where, v.Type())
	}
	return nil
}

func kindName(k Kind) string {
	if k == Mapping {
		return "mapping"
	}
	return "list"
}

func decodeStruct(path string, n *Node, v reflect.Value) error {
	if n.Kind != Mapping {
		return fmt.Errorf("%s: want a block of key/value pairs, got a %s (line %d)", path, kindName(n.Kind), n.Line)
	}
	byName := map[string]int{}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		name := f.Tag.Get("yaml")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		byName[name] = i
	}
	for _, key := range n.Keys {
		i, known := byName[key]
		if !known {
			return fmt.Errorf("%s: unknown key %q (line %d); typo or unsupported option", dotted(path, key), key, n.Vals[key].Line)
		}
		if err := decode(dotted(path, key), n.Vals[key], v.Field(i)); err != nil {
			return err
		}
	}
	return nil
}

func decodeSlice(path string, n *Node, v reflect.Value) error {
	if n.Kind != Sequence {
		return fmt.Errorf("%s: want a list, got a %s (line %d)", path, kindName(n.Kind), n.Line)
	}
	out := reflect.MakeSlice(v.Type(), len(n.Items), len(n.Items))
	for i, item := range n.Items {
		if err := decode(fmt.Sprintf("%s[%d]", path, i), item, out.Index(i)); err != nil {
			return err
		}
	}
	v.Set(out)
	return nil
}

func dotted(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
