# sops-editor-online

A single-page editor for [SOPS](https://github.com/getsops/sops)-encrypted YAML
files that use [age](https://age-encryption.org) keys. It is one self-contained
`index.html` that works offline, on a phone, and never sends anything anywhere.

1. Pick an encrypted `.yaml` file (or paste its contents).
2. Paste the contents of your age `keys.txt`.
3. Edit the values in a form (or as raw YAML).
4. Download the re-encrypted file, or copy it to the clipboard.

## Using it

- **GitHub Pages:** enable Pages for this repository (Settings → Pages →
  *Deploy from a branch*, pick the branch and `/ (root)`), then open
  `https://micleo2.github.io/sops-editor-online/` on your phone.
- **Offline:** download `index.html` and open it in a browser. Everything,
  including the WebAssembly engine, is embedded in that one file.

## How it works

The SOPS format logic is not reimplemented in JavaScript. `wasm/` is a small Go
program compiled to WebAssembly that contains:

- `wasm/sopscore/tree.go`, `aes.go`, `yamlstore.go`: the tree walking,
  encryption rules (`unencrypted_suffix`, `encrypted_regex`, comment regexes,
  `mac_only_encrypted`, …), MAC computation, AES-256-GCM value cipher and YAML
  store, copied from the SOPS v3.9.4 sources with only logging removed.
- The real [`filippo.io/age`](https://github.com/FiloSottile/age) library to
  decrypt the file's data key, and SOPS's own Shamir package for files with
  several key groups.

Saving works like `sops edit`: the data key and recipients are kept, values you
did not change keep their exact ciphertext, and `lastmodified` and the MAC are
updated. The page has a Content Security Policy of `default-src 'none'`, so the
browser blocks every network request.

## Building

Requires Go and Node.js.

```sh
./build.sh      # writes index.html
```

The build is reproducible for a given Go version, so you can rebuild and compare
the hash with the committed `index.html`.

Tests compare against fixtures made with the real `sops` and `age` binaries
(the keys in `wasm/sopscore/testdata` are throwaway test keys). With `sops` on
your `PATH`, the tests also check that `sops decrypt` accepts files written by
the editor:

```sh
cd wasm && go test ./...
```

## License

The files derived from SOPS are under the Mozilla Public License 2.0, like SOPS
itself.
