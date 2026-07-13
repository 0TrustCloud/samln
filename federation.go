package samln

import (
	"fmt"
	"strings"
	"time"
)

// FederationAssertion compiles a SAMLn JWT for cross-product SSO.
func (se *SAMLnEngine) FederationAssertion(jti, subject, audience, returnTo string, ttl time.Duration) (string, error) {
	jti = strings.TrimSpace(jti)
	subject = strings.TrimSpace(subject)
	audience = strings.TrimSpace(audience)
	returnTo = strings.TrimSpace(returnTo)
	if jti == "" || subject == "" || audience == "" {
		return "", fmt.Errorf("jti, subject, and audience are required")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	script := fmt.Sprintf(`
		assertion#%s (
			subject("%s"),
			attribute:name."aud"("%s"),
			attribute:name."return_to"("%s"),
			attribute:name."federation"("samln-sso")
		)
	`, jti, subject, audience, returnTo)

	vars := map[string]interface{}{
		"sub": subject,
		"aud": audience,
		"exp": time.Now().Add(ttl).Unix(),
	}
	return se.CompileSAMLnString(script, vars)
}