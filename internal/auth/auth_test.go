package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name:    "no auth header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed header",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "valid header",
			headers: http.Header{"Authorization": []string{"ApiKey secret123"}},
			want:    "secret123",
			wantErr: nil,
		},
		{
			name:    "incorrect prefix",
			headers: http.Header{"Authorization": []string{"Bearer secret123"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "too many parts",
			headers: http.Header{"Authorization": []string{"ApiKey secret123 extra"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if (err != nil) != (tt.wantErr != nil) {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
