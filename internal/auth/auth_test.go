package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		input   http.Header
		want    string
		wantErr error
	}

	tests := []test{
		{input: http.Header{
			"Host":          {"www.host.com"},
			"Content-Type":  {"application/json"},
			"Authorization": {""},
		},
			want: "", wantErr: ErrNoAuthHeaderIncluded},
		{input: http.Header{
			"Host":          {"www.host.com"},
			"Content-Type":  {"application/json"},
			"Authorization": {"Bearer Token"},
		},
			want: "", wantErr: errors.New("malformed authorization header")},
		{input: http.Header{
			"ApiKey":        {"1234"},
			"Host":          {"www.host.com"},
			"Content-Type":  {"application/json"},
			"Authorization": {"Bearer Token"},
		},
			want: "", wantErr: errors.New("malformed authorization header")},
	}

	for _, tc := range tests {
		got, error := GetAPIKey(tc.input)
		if !reflect.DeepEqual(tc.want, got) {
			t.Fatalf("expected: %v, got: %v", tc.want, got)
		}
		if !reflect.DeepEqual(tc.wantErr, error) {
			t.Fatalf("expected: %v, got: %v", tc.wantErr, error)
		}
	}
}
