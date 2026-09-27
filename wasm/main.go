//go:build js && wasm

// Command wasm exposes the SOPS editor core to JavaScript.
//
// Every function takes and returns strings; results are JSON objects of the
// form {"ok": true, ...} or {"ok": false, "error": "..."}.
package main

import (
	"encoding/json"
	"syscall/js"
	"time"

	"github.com/micleo2/sops-editor-online/wasm/sopscore"
)

var session *sopscore.Session

func result(fields map[string]interface{}) string {
	fields["ok"] = true
	b, err := json.Marshal(fields)
	if err != nil {
		return failure(err)
	}
	return string(b)
}

func failure(err error) string {
	b, _ := json.Marshal(map[string]interface{}{"ok": false, "error": err.Error()})
	return string(b)
}

func parseDocs(s string) (sopscore.TreeBranches, error) {
	var docs []sopscore.Node
	if err := json.Unmarshal([]byte(s), &docs); err != nil {
		return nil, err
	}
	return sopscore.FromJSONModel(docs)
}

func settings() sopscore.Metadata {
	if session == nil {
		return sopscore.Metadata{UnencryptedSuffix: sopscore.DefaultUnencryptedSuffix}
	}
	return session.Settings
}

// open(encryptedFile, ageKeys, ignoreMAC, fileName)
func open(args []js.Value) string {
	content := []byte(args[0].String())
	format := sopscore.DetectFormat(args[3].String(), content)
	s, err := sopscore.Open(content, args[1].String(), args[2].Truthy(), format)
	if err != nil {
		return failure(err)
	}
	docs, err := sopscore.ToJSONModel(s.Branches, s.Settings)
	if err != nil {
		return failure(err)
	}
	session = s
	return result(map[string]interface{}{"docs": docs, "recipients": s.Recipients, "format": s.Format})
}

// encrypt(docsJSON) -> encrypted file
func encrypt(args []js.Value) string {
	branches, err := parseDocs(args[0].String())
	if err != nil {
		return failure(err)
	}
	out, err := session.Encrypt(branches, time.Now())
	if err != nil {
		return failure(err)
	}
	return result(map[string]interface{}{"output": string(out)})
}

// toText(docsJSON) -> plaintext file in the session's format
func toText(args []js.Value) string {
	branches, err := parseDocs(args[0].String())
	if err != nil {
		return failure(err)
	}
	out, err := sopscore.EmitPlain(session.Format, branches)
	if err != nil {
		return failure(err)
	}
	return result(map[string]interface{}{"text": string(out)})
}

// fromText(plaintext) -> docs
func fromText(args []js.Value) string {
	branches, err := sopscore.LoadPlain(session.Format, []byte(args[0].String()))
	if err != nil {
		return failure(err)
	}
	docs, err := sopscore.ToJSONModel(branches, settings())
	if err != nil {
		return failure(err)
	}
	return result(map[string]interface{}{"docs": docs})
}

// annotate(docsJSON) -> docs with fresh encryption flags
func annotate(args []js.Value) string {
	var in []sopscore.Node
	if err := json.Unmarshal([]byte(args[0].String()), &in); err != nil {
		return failure(err)
	}
	docs, err := sopscore.AnnotateJSONModel(in, settings())
	if err != nil {
		return failure(err)
	}
	return result(map[string]interface{}{"docs": docs})
}

func closeSession([]js.Value) string {
	session = nil
	return result(map[string]interface{}{})
}

func export(name string, f func([]js.Value) string, needsSession bool) {
	js.Global().Get("sopsCore").Set(name, js.FuncOf(func(this js.Value, args []js.Value) (ret interface{}) {
		defer func() {
			if r := recover(); r != nil {
				b, _ := json.Marshal(map[string]interface{}{"ok": false, "error": "internal error"})
				ret = string(b)
			}
		}()
		if needsSession && session == nil {
			b, _ := json.Marshal(map[string]interface{}{"ok": false, "error": "No file is open."})
			return string(b)
		}
		return f(args)
	}))
}

func main() {
	js.Global().Set("sopsCore", js.Global().Get("Object").New())
	export("open", open, false)
	export("encrypt", encrypt, true)
	export("toText", toText, true)
	export("fromText", fromText, true)
	export("annotate", annotate, false)
	export("close", closeSession, false)
	if ready := js.Global().Get("onSopsCoreReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}
	select {}
}
