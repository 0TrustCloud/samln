package samln

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/0TrustCloud/ultimate_db"
	"github.com/golang-jwt/jwt/v5"
)

// ValidateAssertion checks a SAMLn JWT signature, expiry, audience, and replay ledger.
func (se *SAMLnEngine) ValidateAssertion(tokenString, audience string) (subject string, err error) {
	tokenString = strings.TrimSpace(tokenString)
	audience = strings.TrimSpace(strings.ToLower(audience))
	if tokenString == "" {
		return "", errors.New("empty assertion")
	}

	se.mu.RLock()
	signingKey := se.signingKey
	issuer := se.issuer
	authPageID := se.authPageID
	se.mu.RUnlock()

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
		}
		return &signingKey.PublicKey, nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid assertion signature: %w", err)
	}

	if iss, _ := claims["iss"].(string); iss != "" && issuer != "" && !strings.EqualFold(iss, issuer) {
		return "", errors.New("issuer mismatch")
	}

	expRaw, ok := claims["exp"]
	if !ok {
		return "", errors.New("missing exp")
	}
	var exp int64
	switch v := expRaw.(type) {
	case float64:
		exp = int64(v)
	case json.Number:
		exp, _ = v.Int64()
	default:
		return "", errors.New("invalid exp")
	}
	if time.Now().Unix() > exp {
		return "", errors.New("assertion expired")
	}

	sub, _ := claims["sub"].(string)
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return "", errors.New("missing subject")
	}

	if audience != "" && !assertionAudienceMatches(claims["aud"], audience) {
		return "", errors.New("audience mismatch")
	}

	jti, _ := claims["jti"].(string)
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return "", errors.New("missing jti")
	}
	if se.assertionConsumed(authPageID, jti) {
		return "", errors.New("assertion already consumed")
	}

	return sub, nil
}

func assertionAudienceMatches(raw interface{}, audience string) bool {
	audience = strings.TrimSpace(strings.ToLower(audience))
	switch v := raw.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(v), audience)
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.EqualFold(strings.TrimSpace(s), audience) {
				return true
			}
		}
	}
	return false
}

func (se *SAMLnEngine) assertionConsumed(pageID ultimate_db.PageID, jti string) bool {
	txn := se.DB.BeginTxn()
	raw, err := se.DB.Read(pageID, txn, []byte("assertion:"+jti))
	se.DB.CommitTxn(txn)
	if err != nil || len(raw) == 0 {
		return false
	}
	var payload map[string]interface{}
	if json.Unmarshal(raw, &payload) != nil {
		return false
	}
	status, _ := payload["status"].(string)
	return strings.EqualFold(status, "consumed")
}

func (se *SAMLnEngine) ConsumeAssertion(pageID ultimate_db.PageID, jti, subject string) error {
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return errors.New("missing jti")
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"jti":     jti,
		"subject": subject,
		"status":  "consumed",
		"used_at": time.Now().UTC().Format(time.RFC3339),
	})
	txn := se.DB.BeginTxn()
	if err := se.DB.Write(pageID, txn, []byte("assertion:"+jti), payload, ""); err != nil {
		return err
	}
	se.DB.CommitTxn(txn)
	return nil
}

// ValidateHardwareAssertion verifies a hardware-bound SAMLn token against ultimate_db.
func (se *SAMLnEngine) ValidateHardwareAssertion(tokenString, expectedChallenge string) (bool, error) {
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return false, errors.New("empty assertion")
	}

	se.mu.RLock()
	signingKey := se.signingKey
	authPageID := se.authPageID
	se.mu.RUnlock()

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return &signingKey.PublicKey, nil
	})
	if err != nil || !token.Valid {
		return false, fmt.Errorf("invalid assertion: %w", err)
	}

	sub, _ := claims["sub"].(string)
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return false, errors.New("missing subject")
	}

	devBind, _ := claims["saml:DeviceBinding"].(map[string]interface{})
	if expectedChallenge != "" {
		challenge, _ := devBind["Challenge"].(string)
		if challenge != expectedChallenge {
			return false, errors.New("device binding challenge mismatch")
		}
	}

	hwSig, _ := claims["saml:NoiseSignature"].(map[string]interface{})
	proofB64, _ := hwSig["Proof"].(string)
	if strings.TrimSpace(proofB64) == "" {
		return false, errors.New("missing hardware proof")
	}
	proof, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		return false, fmt.Errorf("invalid hardware proof encoding: %w", err)
	}

	jti, _ := claims["jti"].(string)
	payload := fmt.Sprintf("%s|%s", jti, sub)
	hash := sha256.Sum256([]byte(payload))

	txn := se.DB.BeginTxn()
	userBytes, err := se.DB.Read(authPageID, txn, []byte("user:"+sub))
	se.DB.CommitTxn(txn)
	if err != nil || len(userBytes) == 0 {
		return false, errors.New("subject not registered for hardware validation")
	}

	var userRecord map[string]interface{}
	if json.Unmarshal(userBytes, &userRecord) != nil {
		return false, errors.New("corrupt user hardware record")
	}
	idRaw, ok := userRecord["id"]
	if !ok {
		return false, errors.New("missing hardware public key bytes")
	}
	pubKey, err := hardwarePublicKeyFromRecord(userRecord)
	if err != nil || pubKey == nil {
		return false, fmt.Errorf("hardware key parse failure: %w", err)
	}
	_ = idRaw

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], proof); err != nil {
		return false, errors.New("hardware signature rejected")
	}
	return true, nil
}

func hardwarePublicKeyFromRecord(userRecord map[string]interface{}) (*rsa.PublicKey, error) {
	if modB64, ok := userRecord["modulus"].(string); ok && modB64 != "" {
		modBytes, err := base64.StdEncoding.DecodeString(modB64)
		if err != nil {
			return nil, err
		}
		exp := 65537
		if raw, ok := userRecord["exponent"].(float64); ok && int(raw) > 0 {
			exp = int(raw)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(modBytes), E: exp}, nil
	}
	return nil, errors.New("no hardware public key on record")
}