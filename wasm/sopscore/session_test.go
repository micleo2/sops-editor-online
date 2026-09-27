package sopscore

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixtures in testdata/ were created with the real sops (v3.9.4) and age
// binaries; *.expected.yaml is the output of `sops decrypt`.
var fixtures = []struct {
	name string
	keys string
}{
	{"basic", "key1.txt"},
	{"regex", "key2.txt"},
	{"maconly", "key1.txt"},
	{"multidoc", "key1.txt"},
	{"shamir", "keys12.txt"},
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func open(t *testing.T, enc []byte, keys string) *Session {
	t.Helper()
	s, err := Open(enc, string(read(t, keys)), false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// roundTripModel sends the branches through the JSON model, as the UI does.
func roundTripModel(t *testing.T, s *Session) TreeBranches {
	t.Helper()
	docs, err := ToJSONModel(s.Branches, s.Settings)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(docs)
	if err != nil {
		t.Fatal(err)
	}
	var back []Node
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	branches, err := FromJSONModel(back)
	if err != nil {
		t.Fatal(err)
	}
	return branches
}

func TestDecryptMatchesSops(t *testing.T) {
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			s := open(t, read(t, f.name+".enc.yaml"), f.keys)
			got, err := EmitPlain(s.Branches)
			if err != nil {
				t.Fatal(err)
			}
			if want := read(t, f.name+".expected.yaml"); !bytes.Equal(got, want) {
				t.Errorf("plaintext mismatch\n--- got\n%s\n--- want\n%s", got, want)
			}
		})
	}
}

func TestReencryptRoundTrip(t *testing.T) {
	sopsBin, _ := exec.LookPath("sops")
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			input := read(t, f.name+".enc.yaml")
			s := open(t, input, f.keys)
			out, err := s.Encrypt(roundTripModel(t, s), time.Now())
			if err != nil {
				t.Fatal(err)
			}

			// Unchanged values keep their ciphertext (like `sops edit`), so
			// only lastmodified and the MAC may differ.
			inLines, outLines := strings.Split(string(input), "\n"), strings.Split(string(out), "\n")
			if len(inLines) != len(outLines) {
				t.Fatalf("line count changed: %d -> %d\n%s", len(inLines), len(outLines), out)
			}
			for i := range inLines {
				l := strings.TrimSpace(inLines[i])
				if inLines[i] != outLines[i] && !strings.HasPrefix(l, "lastmodified:") && !strings.HasPrefix(l, "mac:") {
					t.Errorf("line %d changed:\n  %s\n  %s", i+1, inLines[i], outLines[i])
				}
			}

			// Our own decryption of the result.
			s2 := open(t, out, f.keys)
			got, _ := EmitPlain(s2.Branches)
			want := read(t, f.name+".expected.yaml")
			if !bytes.Equal(got, want) {
				t.Errorf("re-decrypted plaintext mismatch\n%s", got)
			}

			// The real sops binary must accept the result too.
			if sopsBin == "" {
				t.Skip("sops not on PATH")
			}
			cmd := exec.Command(sopsBin, "decrypt", "--input-type", "yaml", "--output-type", "yaml", "/dev/stdin")
			cmd.Stdin = bytes.NewReader(out)
			cmd.Env = append(os.Environ(), "SOPS_AGE_KEY_FILE="+filepath.Join("testdata", f.keys))
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			plain, err := cmd.Output()
			if err != nil {
				t.Fatalf("sops decrypt failed: %v\n%s\n%s", err, stderr.String(), out)
			}
			if !bytes.Equal(plain, want) {
				t.Errorf("sops decrypt mismatch\n%s", plain)
			}
		})
	}
}

func TestEditIsVisibleToSops(t *testing.T) {
	sopsBin, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("sops not on PATH")
	}
	s := open(t, read(t, "basic.enc.yaml"), "key1.txt")
	docs, _ := ToJSONModel(s.Branches, s.Settings)
	db := docs[0].Items[1].V
	db.Items[2].V.V = "correct horse" // password
	key := "token"
	docs[0].Items = append(docs[0].Items, Item{K: &key, V: &Node{T: "int", V: "7"}})
	branches, err := FromJSONModel(docs)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Encrypt(branches, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sopsBin, "decrypt", "--input-type", "yaml", "--output-type", "yaml", "/dev/stdin")
	cmd.Stdin = bytes.NewReader(out)
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY_FILE=testdata/key1.txt")
	plain, err := cmd.Output()
	if err != nil {
		t.Fatalf("sops decrypt failed: %v", err)
	}
	if !strings.Contains(string(plain), "password: correct horse\n") || !strings.Contains(string(plain), "token: 7\n") {
		t.Errorf("edit not visible:\n%s", plain)
	}
}

func TestErrors(t *testing.T) {
	enc := read(t, "basic.enc.yaml")
	if _, err := Open(enc, string(read(t, "key2.txt")), false); err == nil || !strings.Contains(err.Error(), "None of the given age keys") {
		t.Errorf("wrong key: got %v", err)
	}
	if _, err := Open(enc, "not a key", false); err == nil {
		t.Error("garbage identity accepted")
	}
	if _, err := Open([]byte("a: 1\n"), string(read(t, "key1.txt")), false); err == nil || !strings.Contains(err.Error(), "No SOPS metadata") {
		t.Errorf("plain file: got %v", err)
	}
	// Tampering with an unencrypted value must break the MAC.
	tampered := bytes.Replace(enc, []byte("db.example.com"), []byte("evil.example.com"), 1)
	if _, err := Open(tampered, string(read(t, "key1.txt")), false); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Errorf("tampered: got %v", err)
	}
	if _, err := Open(tampered, string(read(t, "key1.txt")), true); err != nil {
		t.Errorf("ignoreMAC: got %v", err)
	}
	// Shamir needs two of the three groups.
	if _, err := Open(read(t, "shamir.enc.yaml"), string(read(t, "key1.txt")), false); err == nil {
		t.Error("shamir opened with a single group")
	}
}

func TestEncryptionFlags(t *testing.T) {
	s := open(t, read(t, "basic.enc.yaml"), "key1.txt")
	docs, _ := ToJSONModel(s.Branches, s.Settings)
	db := docs[0].Items[1].V
	for _, item := range db.Items {
		if item.K == nil || item.V.Enc == nil {
			continue
		}
		want := *item.K != "host_unencrypted"
		if *item.V.Enc != want {
			t.Errorf("%s: enc=%v, want %v", *item.K, *item.V.Enc, want)
		}
	}
	r := open(t, read(t, "regex.enc.yaml"), "key1.txt")
	docs, _ = ToJSONModel(r.Branches, r.Settings)
	for _, item := range docs[0].Items[1].V.Items {
		if item.K != nil && item.V.Enc != nil && *item.V.Enc != (*item.K == "password") {
			t.Errorf("regex %s: enc=%v", *item.K, *item.V.Enc)
		}
	}
}
