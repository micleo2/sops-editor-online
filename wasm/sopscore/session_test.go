package sopscore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var inlineComment = regexp.MustCompile(`(?m)^( *)(.*\S) (#ENC\[[^\]]*type:comment\])$`)

// Fixtures in testdata/ were created with the real sops (v3.9.4) and age
// binaries; *.expected.yaml is the output of `sops decrypt`.
// Files named v313-* were created with sops v3.13.3, the others with v3.9.4.
var fixtures = []struct {
	name string
	ext  string
	keys string
}{
	{"basic", "yaml", "key1.txt"},
	{"regex", "yaml", "key2.txt"},
	{"maconly", "yaml", "key1.txt"},
	{"multidoc", "yaml", "key1.txt"},
	{"shamir", "yaml", "keys12.txt"},
	{"v313-basic", "yaml", "key1.txt"},
	{"v313-dotenv", "env", "key2.txt"},
	{"v313-regex", "env", "key1.txt"},
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func open(t *testing.T, enc []byte, keys string, format Format) *Session {
	t.Helper()
	s, err := Open(enc, string(read(t, keys)), false, format)
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
			encName := f.name + ".enc." + f.ext
			enc := read(t, encName)
			format := DetectFormat(encName, enc)
			if detected := DetectFormat("", enc); detected != format {
				t.Errorf("content sniffing detected %s, want %s", detected, format)
			}
			s := open(t, enc, f.keys, format)
			got, err := EmitPlain(format, s.Branches)
			if err != nil {
				t.Fatal(err)
			}
			if want := read(t, f.name+".expected."+f.ext); !bytes.Equal(got, want) {
				t.Errorf("plaintext mismatch\n--- got\n%s\n--- want\n%s", got, want)
			}
		})
	}
}

func TestReencryptRoundTrip(t *testing.T) {
	sopsBin, _ := exec.LookPath("sops")
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			input := read(t, f.name+".enc."+f.ext)
			format := DetectFormat(f.name+".enc."+f.ext, input)
			s := open(t, input, f.keys, format)
			out, err := s.Encrypt(roundTripModel(t, s), time.Now())
			if err != nil {
				t.Fatal(err)
			}

			// Unchanged values keep their ciphertext (like `sops edit`), so
			// only lastmodified and the MAC may differ.
			// SOPS (and `sops edit`) loses the inline flag of comments when
			// decrypting, so they move onto their own line.
			normalized := inlineComment.ReplaceAllString(string(input), "$1$3\n$1$2")
			inLines, outLines := strings.Split(normalized, "\n"), strings.Split(string(out), "\n")
			if len(inLines) != len(outLines) {
				t.Fatalf("line count changed: %d -> %d\n%s", len(inLines), len(outLines), out)
			}
			for i := range inLines {
				l := strings.TrimSpace(inLines[i])
				if inLines[i] != outLines[i] && !strings.HasPrefix(strings.TrimPrefix(l, "sops_"), "lastmodified") && !strings.HasPrefix(strings.TrimPrefix(l, "sops_"), "mac") {
					t.Errorf("line %d changed:\n  %s\n  %s", i+1, inLines[i], outLines[i])
				}
			}

			// Our own decryption of the result.
			s2 := open(t, out, f.keys, format)
			got, _ := EmitPlain(format, s2.Branches)
			want := read(t, f.name+".expected."+f.ext)
			if !bytes.Equal(got, want) {
				t.Errorf("re-decrypted plaintext mismatch\n%s", got)
			}

			// The real sops binary must accept the result too.
			if sopsBin == "" {
				t.Skip("sops not on PATH")
			}
			if strings.HasPrefix(f.name, "v313-") && !sopsAtLeast313(sopsBin) {
				t.Skip("fixture needs sops >= 3.13")
			}
			tmp := filepath.Join(t.TempDir(), "out."+f.ext)
			if err := os.WriteFile(tmp, out, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(sopsBin, "decrypt", tmp)
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
	s := open(t, read(t, "basic.enc.yaml"), "key1.txt", FormatYAML)
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
	tmp := filepath.Join(t.TempDir(), "out.yaml")
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sopsBin, "decrypt", tmp)
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
	if _, err := Open(enc, string(read(t, "key2.txt")), false, FormatYAML); err == nil || !strings.Contains(err.Error(), "None of the given age keys") {
		t.Errorf("wrong key: got %v", err)
	}
	if _, err := Open(enc, "not a key", false, FormatYAML); err == nil {
		t.Error("garbage identity accepted")
	}
	if _, err := Open([]byte("a: 1\n"), string(read(t, "key1.txt")), false, FormatYAML); err == nil || !strings.Contains(err.Error(), "No SOPS metadata") {
		t.Errorf("plain file: got %v", err)
	}
	// Tampering with an unencrypted value must break the MAC.
	tampered := bytes.Replace(enc, []byte("db.example.com"), []byte("evil.example.com"), 1)
	if _, err := Open(tampered, string(read(t, "key1.txt")), false, FormatYAML); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Errorf("tampered: got %v", err)
	}
	if _, err := Open(tampered, string(read(t, "key1.txt")), true, FormatYAML); err != nil {
		t.Errorf("ignoreMAC: got %v", err)
	}
	// Shamir needs two of the three groups.
	if _, err := Open(read(t, "shamir.enc.yaml"), string(read(t, "key1.txt")), false, FormatYAML); err == nil {
		t.Error("shamir opened with a single group")
	}
}

func TestEncryptionFlags(t *testing.T) {
	s := open(t, read(t, "basic.enc.yaml"), "key1.txt", FormatYAML)
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
	r := open(t, read(t, "regex.enc.yaml"), "key1.txt", FormatYAML)
	docs, _ = ToJSONModel(r.Branches, r.Settings)
	for _, item := range docs[0].Items[1].V.Items {
		if item.K != nil && item.V.Enc != nil && *item.V.Enc != (*item.K == "password") {
			t.Errorf("regex %s: enc=%v", *item.K, *item.V.Enc)
		}
	}
}

func TestDotenvEdit(t *testing.T) {
	s := open(t, read(t, "v313-dotenv.enc.env"), "key1.txt", FormatDotenv)
	docs, _ := ToJSONModel(s.Branches, s.Settings)
	key := "NEW_SECRET"
	docs[0].Items = append(docs[0].Items, Item{K: &key, V: &Node{T: "str", V: "a\nb"}})
	branches, err := FromJSONModel(docs)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Encrypt(branches, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s2 := open(t, out, "key2.txt", FormatDotenv)
	plain, _ := EmitPlain(FormatDotenv, s2.Branches)
	if !strings.HasSuffix(string(plain), "NEW_SECRET=a\\nb\n") {
		t.Errorf("new value missing:\n%s", plain)
	}
	// Metadata stays at the end, in the original order.
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if !strings.HasPrefix(lines[len(lines)-1], "sops_version=") || !strings.HasPrefix(lines[len(lines)-9], "NEW_SECRET=ENC[") {
		t.Errorf("unexpected layout:\n%s", out)
	}
	bad := "BAD=KEY"
	docs[0].Items = append(docs[0].Items, Item{K: &bad, V: &Node{T: "str"}})
	branches, _ = FromJSONModel(docs)
	if _, err := s.Encrypt(branches, time.Now()); err == nil {
		t.Error("key containing = accepted")
	}
	reserved := "sops_x"
	docs[0].Items[len(docs[0].Items)-1].K = &reserved
	branches, _ = FromJSONModel(docs)
	if _, err := s.Encrypt(branches, time.Now()); err == nil {
		t.Error("reserved sops_ key accepted")
	}
}

func sopsAtLeast313(bin string) bool {
	out, _ := exec.Command(bin, "--version", "--disable-version-check").Output()
	var major, minor int
	for _, field := range strings.Fields(string(out)) {
		if n, _ := fmt.Sscanf(field, "%d.%d", &major, &minor); n == 2 {
			return major > 3 || (major == 3 && minor >= 13)
		}
	}
	return false
}
