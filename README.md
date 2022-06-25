# turbo-auth

Providers exposed
1. Basic-Auth
2. JWT
3. OAuth2

## Sub Providers
1. Basic-Auth
   1. database
   2. ldap

   
JWT
other implementation
token sent in request -> jwt middleware applied in go-turbo -> Apply function called -> internal handleRequest function called
-> fetch credentials from the request header -> fetch authToken, refreshToken, csrf -> assign the extracted values to the creds struct


Simple implementation
issue new token -> func
validate token -> func

config {
   signingKey: file or string
   signingMethod: HS256 or RS256
   bearerTokens: bool -> tokens can be fetched from header or cookie
   refreshTokenValidTime: time.Duration
   authTokenValidTime:    time.Duration
   authTokenName:         string
   refreshTokenName:      string
}

apply() {
   if (token is expired){
      issue_new_token()
   }
   
   validate_incoming_token()
   if (err) {
      return 403 from middleware
   }
}