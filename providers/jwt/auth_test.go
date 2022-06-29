package jwt

import (
	turbo_auth "github.com/nandlabs/turbo-auth"
	turboError "github.com/nandlabs/turbo-auth/errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestJwtAuthConfig_IssueNewToken(t *testing.T) {
	type fields struct {
		SigningKey            string
		SigningMethod         string
		BearerTokens          bool
		RefreshTokenValidTime time.Duration
		AuthTokenValidTime    time.Duration
		AuthTokenName         string
		RefreshTokenName      string
	}
	type args struct {
		username string
		duration time.Duration
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		want       string
		wantErr    bool
		errCode    int
		errMessage string
	}{
		{
			name: "Test_correct_data",
			fields: fields{
				SigningKey:            "test_key",
				SigningMethod:         "HS256",
				BearerTokens:          false,
				RefreshTokenValidTime: 0,
				AuthTokenValidTime:    0,
				AuthTokenName:         "",
				RefreshTokenName:      "",
			},
			args: args{
				username: "test_user",
				duration: 5,
			},
			want:       "",
			wantErr:    false,
			errCode:    0,
			errMessage: "",
		},
		{
			name: "Test_wrong_signing_method",
			fields: fields{
				SigningKey:            "test_key",
				SigningMethod:         "DS234",
				BearerTokens:          false,
				RefreshTokenValidTime: 0,
				AuthTokenValidTime:    0,
				AuthTokenName:         "",
				RefreshTokenName:      "",
			},
			args: args{
				username: "test_user",
				duration: 5,
			},
			want:       "",
			wantErr:    true,
			errCode:    406,
			errMessage: "singing method not supported",
		},
		{
			name: "Test_blank_username",
			fields: fields{
				SigningKey:            "test_key",
				SigningMethod:         "HS256",
				BearerTokens:          false,
				RefreshTokenValidTime: 0,
				AuthTokenValidTime:    0,
				AuthTokenName:         "",
				RefreshTokenName:      "",
			},
			args: args{
				username: "",
				duration: 5,
			},
			want:       "",
			wantErr:    true,
			errCode:    406,
			errMessage: "username is required to generate payload",
		},
		{
			name: "Test_blank_duration",
			fields: fields{
				SigningKey:            "test_key",
				SigningMethod:         "HS256",
				BearerTokens:          false,
				RefreshTokenValidTime: 0,
				AuthTokenValidTime:    0,
				AuthTokenName:         "",
				RefreshTokenName:      "",
			},
			args: args{
				username: "test_username",
				duration: 0,
			},
			want:       "",
			wantErr:    true,
			errCode:    406,
			errMessage: "duration cannot be 0",
		},
		{
			name: "Test_blank_signing_key",
			fields: fields{
				SigningKey:            "",
				SigningMethod:         "HS256",
				BearerTokens:          false,
				RefreshTokenValidTime: 0,
				AuthTokenValidTime:    0,
				AuthTokenName:         "",
				RefreshTokenName:      "",
			},
			args: args{
				username: "test_username",
				duration: 3,
			},
			want:       "",
			wantErr:    true,
			errCode:    406,
			errMessage: "signingKey cannot be empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authConfig := &JwtAuthConfig{
				SigningKey:            tt.fields.SigningKey,
				SigningMethod:         tt.fields.SigningMethod,
				BearerTokens:          tt.fields.BearerTokens,
				RefreshTokenValidTime: tt.fields.RefreshTokenValidTime,
				AuthTokenValidTime:    tt.fields.AuthTokenValidTime,
				AuthTokenName:         tt.fields.AuthTokenName,
				RefreshTokenName:      tt.fields.RefreshTokenName,
			}
			got, err := authConfig.IssueNewToken(tt.args.username, tt.args.duration)
			if (err != nil) != tt.wantErr {
				t.Errorf("IssueNewToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				if err.Code != tt.errCode {
					t.Errorf("IssueNewToken() error = %v, wantErr %v", err.Code, tt.errCode)
					return
				}
				if err.Error() != tt.errMessage {
					t.Errorf("IssueNewToken() error = %v, wantErr %v", err.Error(), tt.errMessage)
					return
				}
			} else {
				if got == "" {
					t.Errorf("IssueNewToken() got = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// TODO : jwt verification not working
func TestJwtAuthConfig_HandleRequest(t *testing.T) {
	type fields struct {
		SigningKey            string
		SigningMethod         string
		BearerTokens          bool
		RefreshTokenValidTime time.Duration
		AuthTokenValidTime    time.Duration
		AuthTokenName         string
		RefreshTokenName      string
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *turboError.JwtError
	}{
		{
			name: "Test_correct",
			fields: fields{
				SigningKey:            "test_key",
				SigningMethod:         "HS256",
				BearerTokens:          true,
				RefreshTokenValidTime: 0,
				AuthTokenValidTime:    0,
				AuthTokenName:         "",
				RefreshTokenName:      "",
			},
			args: args{
				w: httptest.NewRecorder(),
				r: req,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authConfig := &JwtAuthConfig{
				SigningKey:            tt.fields.SigningKey,
				SigningMethod:         tt.fields.SigningMethod,
				BearerTokens:          tt.fields.BearerTokens,
				RefreshTokenValidTime: tt.fields.RefreshTokenValidTime,
				AuthTokenValidTime:    tt.fields.AuthTokenValidTime,
				AuthTokenName:         tt.fields.AuthTokenName,
				RefreshTokenName:      tt.fields.RefreshTokenName,
			}
			authConfig = CreateJwtAuthenticator(authConfig)

			tt.args.r.Header.Set(turbo_auth.DefaultBearerAuthTokenHeader, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.jhjnJDIMcXynEO39KVneryyvZKGDFdJCEJvBcsRniWA")
			if got := authConfig.HandleRequest(tt.args.w, tt.args.r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HandleRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
