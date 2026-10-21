package evalcase_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/runner/evalcase"
)

// TestLoadKeysChecksPublicFiles: a public JWK file that is not the public
// key of its role's private scalar stops LoadKeys.
func TestLoadKeysChecksPublicFiles(t *testing.T) {
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := keys["issuer"]; !ok || k.Role != "issuer" || k.Private == nil || k.Public.Kid != "test-issuer-key-1" {
		t.Errorf("issuer key %+v", k)
	}
	if _, ok := keys["ed25519"]; ok {
		t.Error("the Ed25519 pair is listed as an ES256 key")
	}
	root := copyTree(t, "keys")
	writeFile(t, filepath.Join(root, "keys", "issuer.jwk.json"), readFile(t, filepath.Join(root, "keys", "reputation-service.jwk.json")))
	_, err = evalcase.LoadKeys(root)
	wantErr(t, err, "issuer.jwk.json", "role issuer")

	// The same kid on another public point is no better.
	root = copyTree(t, "keys")
	other := bytes.Replace(readFile(t, filepath.Join(root, "keys", "reputation-service.jwk.json")),
		[]byte("test-reputation-service-key-1"), []byte("test-issuer-key-1"), 1)
	if bytes.Contains(other, []byte("reputation")) {
		t.Fatalf("kid not replaced: %s", other)
	}
	writeFile(t, filepath.Join(root, "keys", "issuer.jwk.json"), other)
	_, err = evalcase.LoadKeys(root)
	wantErr(t, err, "issuer.jwk.json", "role issuer")
}

// TestStaleCarriedPayload: under payload_signed the signature covers one
// file and the JWS carries another; a JWS whose carried payload is not the
// decoded file is stale although its signature still verifies over the
// covered file.
func TestStaleCarriedPayload(t *testing.T) {
	const id = "selection/agent-requests-weaker-set"
	root := caseTree(t, id)
	if _, err := evalcase.Load(root, id); err != nil {
		t.Fatalf("unmodified copy: %v", err)
	}
	editJSON(t, root, id+"/contract.json", func(m map[string]any) { m["zz_extra"] = 1 })
	_, err := evalcase.Load(root, id)
	wantErr(t, err, id, "signed/contract.jws", "stale")
}

// TestDirsRules: the directory rules of the generator contract (README
// section Generator contract: signing.json).
func TestDirsRules(t *testing.T) {
	const id = "admission/valid"
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, root string)
		want   []string
	}{
		{"signed files without signing.json", func(t *testing.T, root string) {
			removeFile(t, filepath.Join(root, id, "signing.json"))
		}, []string{id, "holds signed files", "no signing.json"}},
		{"signed file no entry names", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, id, "signed", "extra.jws"), []byte("x"))
		}, []string{"signed/extra.jws", "named by no entry"}},
		{"artifacts absent", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, id, "signing.json"), []byte(`{"presentations":[]}`))
		}, []string{"artifacts is required"}},
		{"unknown member", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) { s["artifact"] = []any{} })
		}, []string{"signing.json"}},
		{"path leaving the case", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				s["artifacts"].([]any)[0].(map[string]any)["decoded"] = "../contract.json"
			})
		}, []string{"artifacts[0]", "not a relative path"}},
		{"presentation typ for an artifact", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				s["artifacts"].([]any)[0].(map[string]any)["typ"] = "pact-presentation+jwt"
			})
		}, []string{"artifacts[0]", "typ"}},
		{"digests naming a later entry", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				s["artifacts"].([]any)[0].(map[string]any)["digests"] = map[string]any{"/x": "signed/reputation.jws"}
			})
		}, []string{"artifacts[0]", "not the signed file of an earlier entry"}},
		{"signed file named twice", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				s["presentations"].([]any)[0].(map[string]any)["signed"] = "signed/contract.jws"
			})
		}, []string{"presentations[0]", "named twice"}},
		{"presentation without jti", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				delete(s["presentations"].([]any)[0].(map[string]any), "jti")
			})
		}, []string{"presentations[0]", "required"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := caseTree(t, id)
			if _, err := evalcase.Dirs(root); err != nil {
				t.Fatalf("unmodified copy: %v", err)
			}
			tc.mutate(t, root)
			_, err := evalcase.Dirs(root)
			wantErr(t, err, tc.want...)
		})
	}

	const multi = "approval/approved-fresh-exchange"
	for _, tc := range []struct{ name, seq, want string }{
		{"no exchanges", `{"exchanges":[],"subject":"exchanges/1"}`, "exchanges is empty"},
		{"exchange outside the case", `{"exchanges":["../x"],"subject":"../x"}`, "not a relative path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := caseTree(t, multi)
			writeFile(t, filepath.Join(root, multi, "sequence.json"), []byte(tc.seq))
			_, err := evalcase.Dirs(root)
			wantErr(t, err, multi, "sequence.json", tc.want)
		})
	}
}

// TestWalkRules: the decoded-file and presentation rules of the generator
// contract, applied by Walk whatever the signed files hold.
func TestWalkRules(t *testing.T) {
	const id = "admission/valid"
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, root string)
		want   []string
	}{
		{"decoded not canonical", func(t *testing.T, root string) {
			p := filepath.Join(root, id, "contract.json")
			writeFile(t, p, append(readFile(t, p), '\n'))
		}, []string{"contract.json", "RFC 8785 canonical"}},
		{"jti not the fixed one", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				s["artifacts"].([]any)[1].(map[string]any)["jti"] = "other"
			})
		}, []string{"evidence/runtime.json", "jti"}},
		{"iat not the fixed one", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				s["artifacts"].([]any)[1].(map[string]any)["iat"] = 1792080001
			})
		}, []string{"evidence/runtime.json", "iat"}},
		{"exp not the stated one", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				s["artifacts"].([]any)[1].(map[string]any)["exp"] = 1
			})
		}, []string{"evidence/runtime.json", "exp"}},
		{"null decoded artifact", func(t *testing.T, root string) {
			writeFile(t, filepath.Join(root, id, "reputation.json"), []byte("null"))
		}, []string{"reputation.json is null"}},
		{"no test key for the signer", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				s["artifacts"].([]any)[0].(map[string]any)["signer"] = "nobody"
			})
		}, []string{"contract.json", "no test key for role nobody"}},
		{"two snapshots and no reputation named", func(t *testing.T, root string) {
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				a := s["artifacts"].([]any)
				a[1].(map[string]any)["typ"] = "pact-reputation+jwt"
			})
		}, []string{"signed/presentation.jws", "2 snapshot artifacts"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := caseTree(t, id)
			tc.mutate(t, root)
			keys, err := evalcase.LoadKeys(root)
			if err != nil {
				t.Fatal(err)
			}
			dirs, err := evalcase.Dirs(root)
			if err != nil {
				t.Fatal(err)
			}
			err = evalcase.Walk(root, dirs[0], keys, func(f evalcase.File) (string, error) { return f.Sign() })
			wantErr(t, err, tc.want...)
		})
	}
}

// TestWalkFiles: Walk hands over each signed file with its typ, key,
// payload and signed bytes, and a fresh signature passes File.Check.
func TestWalkFiles(t *testing.T) {
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := evalcase.Dirs(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(dirs, func(d evalcase.Dir) bool { return d.ID == "selection/agent-requests-weaker-set" })
	if i < 0 {
		t.Fatal("no selection/agent-requests-weaker-set")
	}
	n := 0
	err = evalcase.Walk(repoFixtures, dirs[i], keys, func(f evalcase.File) (string, error) {
		n++
		dir := filepath.Join(repoFixtures, filepath.FromSlash(dirs[i].Path))
		switch f.Signed {
		case "signed/contract.jws":
			// payload_signed: the JWS carries contract.json, the signature
			// covers the file payload_signed names.
			if f.Typ != jws.TypRequirements || f.Key.Role != "issuer" || f.Decoded != "contract.json" ||
				!bytes.Equal(f.Payload, readFile(t, filepath.Join(dir, "contract.json"))) || bytes.Equal(f.Over, f.Payload) {
				t.Errorf("contract file %+v", f)
			}
		case "signed/presentation.jws":
			if f.Typ != jws.TypPresentation || f.Key.Role != "holder" || f.Decoded != "" || !bytes.Equal(f.Over, f.Payload) {
				t.Errorf("presentation file %+v", f)
			}
		}
		fresh, err := f.Sign()
		if err != nil {
			return "", err
		}
		if err := f.Check(fresh); err != nil {
			t.Errorf("%s: a fresh signature fails Check: %v", f.Signed, err)
		}
		committed := string(readFile(t, filepath.Join(dir, filepath.FromSlash(f.Signed))))
		if err := f.Check(committed); err != nil {
			t.Errorf("%s: committed file fails Check: %v", f.Signed, err)
		}
		return committed, nil
	})
	if err != nil || n != len(dirs[i].Signing.Artifacts)+len(dirs[i].Signing.Presentations) {
		t.Errorf("walk: %v after %d files", err, n)
	}
}

// walkPayloads runs Walk over the dir with the id of the tree root and
// returns the payload of each file by signed path.
func walkPayloads(t testing.TB, root, id string) (map[string][]byte, error) {
	t.Helper()
	keys, err := evalcase.LoadKeys(root)
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := evalcase.Dirs(root)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(dirs, func(d evalcase.Dir) bool { return d.ID == id })
	if i < 0 {
		t.Fatalf("Dirs lists no %s", id)
	}
	out := map[string][]byte{}
	err = evalcase.Walk(root, dirs[i], keys, func(f evalcase.File) (string, error) {
		out[f.Signed] = f.Payload
		return f.Sign()
	})
	return out, err
}

// TestPresentationEmbedsEvidenceInOrder: without an evidence member, the
// presentation embeds the compact evidence artifacts in signing.json order.
func TestPresentationEmbedsEvidenceInOrder(t *testing.T) {
	const id = "admission/valid"
	root := caseTree(t, id)
	for _, e := range []struct{ name, jti string }{{"extra-a", "extra-a-jti"}, {"extra-b", "extra-b-jti"}} {
		writeFile(t, filepath.Join(root, id, "evidence", e.name+".json"),
			[]byte(`{"iat":1792080000,"jti":"`+e.jti+`","nbf":1792080000}`))
	}
	editJSON(t, root, id+"/signing.json", func(s map[string]any) {
		a := s["artifacts"].([]any)
		for _, e := range []string{"extra-a", "extra-b"} {
			a = append(a, map[string]any{"decoded": "evidence/" + e + ".json", "signed": "signed/evidence/" + e + ".jws", "typ": "pact-evidence+jwt", "signer": "issuer", "jti": e + "-jti"})
		}
		s["artifacts"] = a
	})
	var got []string
	keys, _ := evalcase.LoadKeys(root)
	dirs, _ := evalcase.Dirs(root)
	signed := map[string]string{}
	err := evalcase.Walk(root, dirs[slices.IndexFunc(dirs, func(d evalcase.Dir) bool { return d.ID == id })], keys, func(f evalcase.File) (string, error) {
		c, err := f.Sign()
		signed[f.Signed] = c
		if f.Typ == jws.TypPresentation {
			var p struct {
				Evidence []string `json:"evidence"`
			}
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				t.Fatal(err)
			}
			got = p.Evidence
		}
		return c, err
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{signed["signed/evidence/runtime.jws"], signed["signed/evidence/extra-a.jws"], signed["signed/evidence/extra-b.jws"]}
	if !slices.Equal(got, want) {
		t.Errorf("presentation evidence %d entries, not the artifacts in signing.json order", len(got))
	}
}

// TestDigestPointers: the digests of an artifact entry set a member of an
// object or replace an element of an array, and name nothing else.
func TestDigestPointers(t *testing.T) {
	const id = "admission/valid"
	for _, tc := range []struct {
		name, ptr, want string
	}{
		{"new member", "/extra", ""},
		{"array element", "/list/1", ""},
		{"array element out of range", "/list/2", "no array element"},
		{"array element with a leading zero", "/list/01", "no array element"},
		{"missing step", "/absent/x", "no member"},
		{"inside a string", "/name/x", "not an object or array"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := caseTree(t, id)
			writeFile(t, filepath.Join(root, id, "evidence", "extra.json"),
				[]byte(`{"iat":1792080000,"jti":"extra-jti","list":[1,2],"name":"n","nbf":1792080000}`))
			editJSON(t, root, id+"/signing.json", func(s map[string]any) {
				s["artifacts"] = append(s["artifacts"].([]any), map[string]any{
					"decoded": "evidence/extra.json", "signed": "signed/evidence/extra.jws", "typ": "pact-evidence+jwt",
					"signer": "issuer", "jti": "extra-jti", "digests": map[string]any{tc.ptr: "signed/contract.jws"},
				})
			})
			payloads, err := walkPayloads(t, root, id)
			if tc.want != "" {
				wantErr(t, err, "evidence/extra.json", tc.ptr, tc.want)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(payloads["signed/evidence/extra.jws"], &m); err != nil {
				t.Fatal(err)
			}
			if tc.ptr == "/extra" && !bytes.Contains(m["extra"], []byte(`"`)) || tc.ptr == "/list/1" && bytes.Equal(m["list"], []byte("[1,2]")) {
				t.Errorf("digest not set: %s", payloads["signed/evidence/extra.jws"])
			}
		})
	}
}
