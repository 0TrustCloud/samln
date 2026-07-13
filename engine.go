package samln

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"text/scanner"
	"time"

	"github.com/0TrustCloud/ultimate_db"
	"github.com/golang-jwt/jwt/v5"
)

type contextKey string
const securityNonceKey contextKey = "samln-nonce"

type SAMLnContext struct {
	W          http.ResponseWriter
	R          *http.Request
	Claims     map[string]interface{}
	TokenNonce string
}

type SAMLnEngine struct {
	DB         *ultimate_db.DB
	Mux        *http.ServeMux
	signingKey *rsa.PrivateKey
	keyID      string
	issuer     string
	authPageID ultimate_db.PageID
	mu         sync.RWMutex
}

func New(db *ultimate_db.DB, issuer string, privateKey *rsa.PrivateKey, authPageID ultimate_db.PageID) (*SAMLnEngine, error) {
	if db == nil || privateKey == nil {
		return nil, errors.New("cannot initialize SAMLn engine without active storage and private key")
	}
	return &SAMLnEngine{
		DB:         db,
		Mux:        http.NewServeMux(),
		signingKey: privateKey,
		keyID:      "samln-v4-noise-decoupled",
		issuer:     issuer,
		authPageID: authPageID,
	}, nil
}

// =============================================================================
// Token Synthesis & Compilation
// =============================================================================

func (se *SAMLnEngine) CompileSAMLnString(script string, variables map[string]interface{}) (string, error) {
	if strings.TrimSpace(script) == "" {
		return "", errors.New("empty samln source schema mapping script")
	}

	parser := NewParser(script)
	nodes, err := parser.Parse()
	if err != nil {
		return "", fmt.Errorf("failed parsing assertion script: %w", err)
	}

	se.mu.RLock()
	issuer := se.issuer
	keyID := se.keyID
	signingKey := se.signingKey
	authPageID := se.authPageID
	se.mu.RUnlock()

	coreClaims := make(jwt.MapClaims)
	coreClaims["iss"] = issuer
	coreClaims["iat"] = time.Now().Unix()

	for k, v := range variables {
		coreClaims[k] = v
	}

	samlAttributes := make(map[string]interface{})
	authnStatement := make(map[string]interface{})
	subjectConfirmation := make(map[string]interface{})
	noiseSig := make(map[string]interface{})
	deviceBinding := make(map[string]interface{})

	var scriptJTI string
	for _, node := range nodes {
		if elem, ok := node.(Element); ok {
			switch strings.ToLower(elem.Tag) {
			case "assertion":
				if id, found := elem.Attributes["id"]; found {
					scriptJTI = id
				}
				coreClaims["saml_issue_instant"] = time.Now().Format(time.RFC3339)
				se.compileNoiseCoreBlocks(elem.Children, coreClaims, samlAttributes, authnStatement, subjectConfirmation, noiseSig, deviceBinding)
			}
		}
	}

	// Enforce a unique token identifier (JTI) for replay attack prevention
	if scriptJTI != "" {
		coreClaims["jti"] = scriptJTI
	} else {
		generatedID, err := generateRandomJTI()
		if err != nil {
			return "", fmt.Errorf("failed generating secure unique token identifier: %w", err)
		}
		coreClaims["jti"] = generatedID
	}

	if len(samlAttributes) > 0 { coreClaims["saml:AttributeStatement"] = samlAttributes }
	if len(authnStatement) > 0 { coreClaims["saml:AuthnStatement"] = authnStatement }
	if len(subjectConfirmation) > 0 { coreClaims["saml:SubjectConfirmation"] = subjectConfirmation }
	if len(noiseSig) > 0 { coreClaims["saml:NoiseSignature"] = noiseSig }
	if len(deviceBinding) > 0 { coreClaims["saml:DeviceBinding"] = deviceBinding }

	if _, exists := coreClaims["exp"]; !exists {
		coreClaims["exp"] = time.Now().Add(1 * time.Hour).Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, coreClaims)
	token.Header["kid"] = keyID
	
	tokenStr, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed signing token profile: %w", err)
	}

	// Atomically record token meta into ultimate_db page and transaction ledger records
	jtiStr, _ := coreClaims["jti"].(string)
	subStr, _ := coreClaims["sub"].(string)
	if err := se.recordTransaction(authPageID, jtiStr, subStr, tokenStr); err != nil {
		return "", fmt.Errorf("token synthesis aborted: storage verification ledger failure: %w", err)
	}

	return tokenStr, nil
}

func (se *SAMLnEngine) compileNoiseCoreBlocks(children []Node, claims jwt.MapClaims, attrs, authn, subConf, noiseSig, devBind map[string]interface{}) {
	for _, child := range children {
		elem, ok := child.(Element)
		if !ok { continue }

		switch strings.ToLower(elem.Tag) {
		case "subject":
			if len(elem.Children) > 0 {
				claims["sub"] = elem.Children[0].Eval()
			}
		case "noisesignature", "hardwaresignature":
			if keyType, found := elem.Attributes["keytype"]; found {
				noiseSig["KeyType"] = keyType
			}
			if proof, found := elem.Attributes["proof"]; found {
				noiseSig["Proof"] = proof
			}
			for _, subChild := range elem.Children {
				if sc, ok := subChild.(Element); ok && strings.ToLower(sc.Tag) == "noisepubkey" {
					noiseSig["NoisePubBytes"] = sc.Children[0].Eval()
				}
			}
		case "devicebinding":
			if sessionRef, found := elem.Attributes["sessionref"]; found {
				devBind["SessionRef"] = sessionRef
			}
			if challenge, found := elem.Attributes["challenge"]; found {
				devBind["Challenge"] = challenge
			}
			for _, subChild := range elem.Children {
				if sc, ok := subChild.(Element); ok && strings.ToLower(sc.Tag) == "dbscpubkey" {
					devBind["DBSCPubKey"] = sc.Children[0].Eval()
				}
			}
		case "attribute":
			if name, found := elem.Attributes["name"]; found && len(elem.Children) > 0 {
				attrs[name] = elem.Children[0].Eval()
			}
		}
	}
}

// =============================================================================
// Storage & Transaction Ledger Execution Path
// =============================================================================

func (se *SAMLnEngine) recordTransaction(pageID ultimate_db.PageID, jti string, subject string, tokenStr string) error {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	
	// Payload maps structured uniformly for ultimate_db storage variants
	dbPayload := map[string]interface{}{
		"jti":        jti,
		"subject":    subject,
		"issued_at":  timestamp,
		"status":     "active",
	}

	ledgerPayload := map[string]interface{}{
		"transaction_id": jti,
		"action":         "SAMLn_TOKEN_GENERATION",
		"subject":        subject,
		"signature_hash": tokenStr[len(tokenStr)-30:], // Slice trailing signature segment for context tracking safely
		"timestamp":      timestamp,
	}

	assertionBytes, err := json.Marshal(dbPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal assertion payload: %w", err)
	}
	ledgerBytes, err := json.Marshal(ledgerPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal ledger payload: %w", err)
	}

	txn := se.DB.BeginTxn()
	if err := se.DB.Write(pageID, txn, []byte("assertion:"+jti), assertionBytes, ""); err != nil {
		return fmt.Errorf("ultimate_db failed to commit data page payload: %w", err)
	}
	if err := se.DB.Write(pageID, txn, []byte("transaction_ledger:"+jti), ledgerBytes, ""); err != nil {
		return fmt.Errorf("transaction_ledger storage write failure: %w", err)
	}
	se.DB.CommitTxn(txn)

	return nil
}

func generateRandomJTI() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// =============================================================================
// Parser Engine Core (Hardened Against DoS & Stack Exhaustion)
// =============================================================================

type Node interface { Eval() string }
type Text string
func (t Text) Eval() string { return string(t) }

type Element struct {
	Tag        string
	Attributes map[string]string
	Children   []Node
}
func (e Element) Eval() string {
	if len(e.Children) > 0 { return e.Children[0].Eval() }
	return ""
}

type Parser struct {
	s        scanner.Scanner
	tok      rune
	depth    int
	maxDepth int
	errs     []string
}

func NewParser(src string) *Parser {
	var s scanner.Scanner
	s.Init(strings.NewReader(src))
	p := &Parser{
		s:        s,
		maxDepth: 25, // Prevents stack overflows from excessively recursive nesting
	}
	p.s.Error = func(s *scanner.Scanner, msg string) {
		p.errs = append(p.errs, fmt.Sprintf("line %d, col %d: %s", s.Position.Line, s.Position.Column, msg))
	}
	p.s.IsIdentRune = func(ch rune, i int) bool {
		return ch == '_' || ch == '-' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
	}
	p.next()
	return p
}

func (p *Parser) next() { p.tok = p.s.Scan() }

func (p *Parser) Parse() ([]Node, error) {
	var nodes []Node
	for p.tok != scanner.EOF {
		node := p.parseExpr()
		if len(p.errs) > 0 {
			return nil, errors.New(strings.Join(p.errs, "; "))
		}
		if node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

func stripQuotes(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '`' && s[len(s)-1] == '`')) {
		return s[1 : len(s)-1]
	}
	return s
}

func (p *Parser) parseExpr() Node {
	p.depth++
	defer func() { p.depth-- }()

	if p.depth > p.maxDepth {
		p.errs = append(p.errs, "maximum nesting limit exceeded")
		return nil
	}

	switch p.tok {
	case scanner.Ident:
		tag := p.s.TokenText()
		p.next()

		attrs := make(map[string]string)
		for p.tok == '.' || p.tok == '#' || p.tok == ':' {
			modifier := p.tok
			p.next()

			if modifier == '.' {
				className := stripQuotes(p.s.TokenText())
				p.next()
				attrs["class"] = strings.TrimSpace(attrs["class"] + " " + className)
			} else if modifier == '#' {
				attrs["id"] = stripQuotes(p.s.TokenText())
				p.next()
			} else if modifier == ':' {
				attrName := strings.ToLower(stripQuotes(p.s.TokenText()))
				p.next()
				attrValue := "true"

				if p.tok == '.' {
					p.next()
					attrValue = stripQuotes(p.s.TokenText())
					p.next()
				}
				attrs[attrName] = attrValue
			}
		}

		var children []Node
		if p.tok == '(' {
			p.next()
			for p.tok != ')' && p.tok != scanner.EOF {
				if arg := p.parseExpr(); arg != nil {
					children = append(children, arg)
				}
				if p.tok == ',' { p.next() }
			}
			if p.tok == ')' { p.next() }
		}
		return Element{Tag: tag, Attributes: attrs, Children: children}

	case scanner.String, scanner.RawString:
		val := stripQuotes(p.s.TokenText())
		p.next()
		return Text(val)

	default:
		p.next()
		return nil
	}
}
