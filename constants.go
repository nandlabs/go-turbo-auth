package turbo_auth

import "time"

// BasicAuth Constants
const (
	Basic               = "basic"
	HeaderAuthorization = "Authorization"
)

// JWT Auth Constants
const (
	DefaultRefreshTokenValidTime  = 72 * time.Hour
	DefaultAuthTokenValidTime     = 15 * time.Minute
	DefaultBearerAuthTokenHeader  = "X-Auth-Token"
	DefaultRefreshAuthTokenHeader = "X-Refresh-Token"
	DefaultCookieAuthTokenName    = "AuthToken"
	DefaultCookieRefreshTokenName = "RefreshToken"
)
