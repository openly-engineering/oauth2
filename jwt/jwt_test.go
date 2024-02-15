// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jwt

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
)

//go:embed dummyPrivateKey.txt
var dummyPrivateKey []byte

func TestJWTFetch_JSONResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "90d64460d14870c08c81352a05dedd3465940a7c",
			"scope": "user",
			"token_type": "bearer",
			"expires_in": 3600
		}`))
	}))
	defer ts.Close()

	conf := &Config{
		Email:      "aaa@xxx.com",
		PrivateKey: dummyPrivateKey,
		TokenURL:   ts.URL,
	}
	tok, err := conf.TokenSource(context.Background()).Token()
	if err != nil {
		t.Fatal(err)
	}
	if !tok.Valid() {
		t.Errorf("got invalid token: %v", tok)
	}
	if got, want := tok.AccessToken, "90d64460d14870c08c81352a05dedd3465940a7c"; got != want {
		t.Errorf("access token = %q; want %q", got, want)
	}
	if got, want := tok.TokenType, "bearer"; got != want {
		t.Errorf("token type = %q; want %q", got, want)
	}
	if got := tok.Expiry.IsZero(); got {
		t.Errorf("token expiry = %v, want none", got)
	}
	scope := tok.Extra("scope")
	if got, want := scope, "user"; got != want {
		t.Errorf("scope = %q; want %q", got, want)
	}
}

func TestJWTFetch_BadResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"scope": "user", "token_type": "bearer"}`))
	}))
	defer ts.Close()

	conf := &Config{
		Email:      "aaa@xxx.com",
		PrivateKey: dummyPrivateKey,
		TokenURL:   ts.URL,
	}
	tok, err := conf.TokenSource(context.Background()).Token()
	if err != nil {
		t.Fatal(err)
	}
	if tok == nil {
		t.Fatalf("got nil token; want token")
	}
	if tok.Valid() {
		t.Errorf("got invalid token: %v", tok)
	}
	if got, want := tok.AccessToken, ""; got != want {
		t.Errorf("access token = %q; want %q", got, want)
	}
	if got, want := tok.TokenType, "bearer"; got != want {
		t.Errorf("token type = %q; want %q", got, want)
	}
	scope := tok.Extra("scope")
	if got, want := scope, "user"; got != want {
		t.Errorf("token scope = %q; want %q", got, want)
	}
}

func TestJWTFetch_BadResponseType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":123, "scope": "user", "token_type": "bearer"}`))
	}))
	defer ts.Close()
	conf := &Config{
		Email:      "aaa@xxx.com",
		PrivateKey: dummyPrivateKey,
		TokenURL:   ts.URL,
	}
	tok, err := conf.TokenSource(context.Background()).Token()
	if err == nil {
		t.Error("got a token; expected error")
		if got, want := tok.AccessToken, ""; got != want {
			t.Errorf("access token = %q; want %q", got, want)
		}
	}
}

func TestJWTFetch_Assertion(t *testing.T) {
	var assertion string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		assertion = r.Form.Get("assertion")

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "90d64460d14870c08c81352a05dedd3465940a7c",
			"scope": "user",
			"token_type": "bearer",
			"expires_in": 3600
		}`))
	}))
	defer ts.Close()

	conf := &Config{
		Email:        "aaa@xxx.com",
		PrivateKey:   dummyPrivateKey,
		PrivateKeyID: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		TokenURL:     ts.URL,
	}

	_, err := conf.TokenSource(context.Background()).Token()
	if err != nil {
		t.Fatalf("Failed to fetch token: %v", err)
	}

	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion = %q; want 3 parts", assertion)
	}
	gotjson, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("invalid token header; err = %v", err)
	}

	got := jws.Header{}
	if err := json.Unmarshal(gotjson, &got); err != nil {
		t.Errorf("failed to unmarshal json token header = %q; err = %v", gotjson, err)
	}

	want := jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	}
	if got != want {
		t.Errorf("access token header = %q; want %q", got, want)
	}
}

func TestJWTFetch_AssertionPayload(t *testing.T) {
	var assertion string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		assertion = r.Form.Get("assertion")

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "90d64460d14870c08c81352a05dedd3465940a7c",
			"scope": "user",
			"token_type": "bearer",
			"expires_in": 3600
		}`))
	}))
	defer ts.Close()

	for _, conf := range []*Config{
		{
			Email:        "aaa1@xxx.com",
			PrivateKey:   dummyPrivateKey,
			PrivateKeyID: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			TokenURL:     ts.URL,
		},
		{
			Email:        "aaa2@xxx.com",
			PrivateKey:   dummyPrivateKey,
			PrivateKeyID: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			TokenURL:     ts.URL,
			Audience:     "https://example.com",
		},
		{
			Email:        "aaa2@xxx.com",
			PrivateKey:   dummyPrivateKey,
			PrivateKeyID: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			TokenURL:     ts.URL,
			PrivateClaims: map[string]interface{}{
				"private0": "claim0",
				"private1": "claim1",
			},
		},
	} {
		t.Run(conf.Email, func(t *testing.T) {
			_, err := conf.TokenSource(context.Background()).Token()
			if err != nil {
				t.Fatalf("Failed to fetch token: %v", err)
			}

			parts := strings.Split(assertion, ".")
			if len(parts) != 3 {
				t.Fatalf("assertion = %q; want 3 parts", assertion)
			}
			gotjson, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("invalid token payload; err = %v", err)
			}

			claimSet := jws.ClaimSet{}
			if err := json.Unmarshal(gotjson, &claimSet); err != nil {
				t.Errorf("failed to unmarshal json token payload = %q; err = %v", gotjson, err)
			}

			if got, want := claimSet.Iss, conf.Email; got != want {
				t.Errorf("payload email = %q; want %q", got, want)
			}
			if got, want := claimSet.Scope, strings.Join(conf.Scopes, " "); got != want {
				t.Errorf("payload scope = %q; want %q", got, want)
			}
			aud := conf.TokenURL
			if conf.Audience != "" {
				aud = conf.Audience
			}
			if got, want := claimSet.Aud, aud; got != want {
				t.Errorf("payload audience = %q; want %q", got, want)
			}
			if got, want := claimSet.Sub, conf.Subject; got != want {
				t.Errorf("payload subject = %q; want %q", got, want)
			}
			if got, want := claimSet.Prn, conf.Subject; got != want {
				t.Errorf("payload prn = %q; want %q", got, want)
			}
			if len(conf.PrivateClaims) > 0 {
				var got interface{}
				if err := json.Unmarshal(gotjson, &got); err != nil {
					t.Errorf("failed to parse payload; err = %q", err)
				}
				m := got.(map[string]interface{})
				for v, k := range conf.PrivateClaims {
					if !reflect.DeepEqual(m[v], k) {
						t.Errorf("payload private claims key = %q: got %#v; want %#v", v, m[v], k)
					}
				}
			}
		})
	}
}

func TestTokenRetrieveError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_grant"}`))
	}))
	defer ts.Close()

	conf := &Config{
		Email:      "aaa@xxx.com",
		PrivateKey: dummyPrivateKey,
		TokenURL:   ts.URL,
	}

	_, err := conf.TokenSource(context.Background()).Token()
	if err == nil {
		t.Fatalf("got no error, expected one")
	}
	_, ok := err.(*oauth2.RetrieveError)
	if !ok {
		t.Fatalf("got %T error, expected *RetrieveError", err)
	}
	// Test error string for backwards compatibility
	expected := fmt.Sprintf("oauth2: cannot fetch token: %v\nResponse: %s", "400 Bad Request", `{"error": "invalid_grant"}`)
	if errStr := err.Error(); errStr != expected {
		t.Fatalf("got %#v, expected %#v", errStr, expected)
	}
}
