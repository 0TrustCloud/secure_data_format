package secure_data_format

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
const securityNonceKey contextKey = "sdf-nonce"

type SecureDataContext struct {
	W          http.ResponseWriter
	R          *http.Request
	Claims     map[string]interface{}
	TokenNonce string
}

type SecureDataEngine struct {
	Store      ultimate_db.KVStore
	LockMgr    ultimate_db.LockManager
	Mux        *http.ServeMux
	signingKey *rsa.PrivateKey
	keyID      string
	issuer     string
	mu         sync.RWMutex
}

type TokenProfile string

const (
	ProfileStructuredLog TokenProfile = "LOG"
	ProfileGrant         TokenProfile = "GRANT"
	ProfileProofOfPoss   TokenProfile = "POP"
)

type DataInvocation struct {
	TargetAddress string                 `json:"target_address"`
	Caller        string                 `json:"caller"`
	Nonce         uint64                 `json:"nonce"`
	Method        string                 `json:"method"`
	Profile       TokenProfile           `json:"profile"`
	Args          map[string]interface{} `json:"args"`
}

// New instantiates the synthesis engine using pluggable interface contracts.
func New(store ultimate_db.KVStore, lockMgr ultimate_db.LockManager, issuer string, privateKey *rsa.PrivateKey) (*SecureDataEngine, error) {
	if store == nil || privateKey == nil {
		return nil, errors.New("cannot initialize SecureData engine without active KVStore and private key")
	}
	return &SecureDataEngine{
		Store:      store,
		LockMgr:    lockMgr,
		Mux:        http.NewServeMux(),
		signingKey: privateKey,
		keyID:      "sdf-v1-crystal-decoupled",
		issuer:     issuer,
	}, nil
}

// =============================================================================
// Polymorphic Token Synthesis & OpenGraph Compilation
// =============================================================================

func (sde *SecureDataEngine) CompileSecureData(script string, tx DataInvocation) (string, error) {
	if strings.TrimSpace(script) == "" {
		return "", errors.New("empty execution target runtime schema script")
	}

	if tx.TargetAddress == "" || tx.Caller == "" {
		return "", errors.New("invalid signature envelope context: missing unique target address or caller identity")
	}

	parser := NewParser(script)
	nodes, err := parser.Parse()
	if err != nil {
		return "", fmt.Errorf("polymorphic token execution parsing failure: %w", err)
	}

	sde.mu.RLock()
	issuer := sde.issuer
	keyID := sde.keyID
	signingKey := sde.signingKey
	sde.mu.RUnlock()

	coreClaims := make(jwt.MapClaims)
	coreClaims["iss"] = issuer
	coreClaims["iat"] = time.Now().Unix()

	var lifespan time.Duration
	switch tx.Profile {
	case ProfileProofOfPoss:
		lifespan = 5 * time.Minute
	case ProfileGrant:
		lifespan = 1 * time.Hour
	case ProfileStructuredLog:
		lifespan = 87600 * time.Hour // 10-year archival lifecycle
	default:
		lifespan = 1 * time.Hour
	}
	coreClaims["exp"] = time.Now().Add(lifespan).Unix()

	coreClaims["target_address"] = tx.TargetAddress
	coreClaims["caller"] = tx.Caller
	coreClaims["nonce"] = tx.Nonce
	coreClaims["method"] = tx.Method
	coreClaims["profile_type"] = string(tx.Profile)

	contractGraph, events := sde.compileOpenGraphGraph(nodes)
	
	statePayload := make(map[string]interface{})
	for k, v := range tx.Args {
		statePayload[k] = v
	}
	for k, v := range contractGraph {
		statePayload[k] = v
	}
	coreClaims["state_updates"] = statePayload

	stateHash, err := computeStateHash(statePayload)
	if err != nil {
		return "", fmt.Errorf("failed calculating deterministic target state hash: %w", err)
	}
	coreClaims["state_root_hash"] = stateHash

	generatedJTI, err := generateRandomJTI()
	if err != nil {
		return "", fmt.Errorf("failed generating structural system transaction jti: %w", err)
	}
	coreClaims["jti"] = generatedJTI

	if len(events) > 0 {
		coreClaims["emitted_events"] = events
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, coreClaims)
	token.Header["kid"] = keyID
	
	tokenStr, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed executing engine cryptographic signature routine: %w", err)
	}

	// Persist changes across isolated storage abstractions
	if err := sde.recordContractStateTransition(generatedJTI, tx, stateHash, events, tokenStr, lifespan); err != nil {
		return "", fmt.Errorf("contract transition halted: persistence engine transaction write error: %w", err)
	}

	return tokenStr, nil
}

func (sde *SecureDataEngine) compileOpenGraphGraph(nodes []Node) (map[string]interface{}, []interface{}) {
	graph := make(map[string]interface{})
	var emittedEvents []interface{}

	for _, node := range nodes {
		elem, ok := node.(Element)
		if !ok { continue }

		tagName := strings.ToLower(elem.Tag)
		nodePayload := make(map[string]interface{})

		for k, v := range elem.Attributes {
			nodePayload[k] = v
		}

		if len(elem.Children) > 0 {
			var complexChildren []interface{}
			var scalarChildren []string

			for _, child := range elem.Children {
				if subElem, ok := child.(Element); ok {
					subGraph, subEvents := sde.compileOpenGraphGraph([]Node{subElem})
					complexChildren = append(complexChildren, subGraph)
					if len(subEvents) > 0 {
						emittedEvents = append(emittedEvents, subEvents...)
					}
				} else {
					scalarChildren = append(scalarChildren, child.Eval())
				}
			}

			if len(complexChildren) > 0 { nodePayload["elements"] = complexChildren }
			if len(scalarChildren) > 1 {
				nodePayload["values"] = scalarChildren
			} else if len(scalarChildren) == 1 {
				nodePayload["value"] = scalarChildren[0]
			}
		}

		if tagName == "event" || tagName == "log" {
			emittedEvents = append(emittedEvents, nodePayload)
			continue
		}

		if existing, found := graph[tagName]; found {
			if existingList, ok := existing.([]interface{}); ok {
				graph[tagName] = append(existingList, nodePayload)
			} else {
				graph[tagName] = []interface{}{existing, nodePayload}
			}
		} else {
			graph[tagName] = nodePayload
		}
	}

	return graph, emittedEvents
}

// =============================================================================
// Abstract Storage Management Layer (2PL + KVStore Integration)
// =============================================================================

func (sde *SecureDataEngine) recordContractStateTransition(jti string, tx DataInvocation, stateHash string, events []interface{}, tokenStr string, lifespan time.Duration) error {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	
	stateUpdateRecord := map[string]interface{}{
		"last_transaction_id": jti,
		"caller":              tx.Caller,
		"nonce":               tx.Nonce,
		"state_root_hash":     stateHash,
		"updated_at":          timestamp,
	}

	ledgerRecord := map[string]interface{}{
		"transaction_id":  jti,
		"target_address":  tx.TargetAddress,
		"caller":          tx.Caller,
		"nonce":           tx.Nonce,
		"method":          tx.Method,
		"profile_type":    string(tx.Profile),
		"state_root_hash": stateHash,
		"emitted_events":  events,
		"signature_hash":  tokenStr[len(tokenStr)-30:], 
		"timestamp":       timestamp,
	}

	worldStateKey := fmt.Sprintf("state:%s:%s", strings.ToLower(string(tx.Profile)), tx.TargetAddress)
	ledgerKey := fmt.Sprintf("transaction_ledger:%s:%s:%d", strings.ToLower(string(tx.Profile)), tx.TargetAddress, tx.Nonce)

	worldStateBytes, err := json.Marshal(stateUpdateRecord)
	if err != nil {
		return fmt.Errorf("failed serializing world state definition structure: %w", err)
	}

	ledgerBytes, err := json.Marshal(ledgerRecord)
	if err != nil {
		return fmt.Errorf("failed serializing immutable transaction receipt: %w", err)
	}

	// 1. Begin isolation boundary using pluggable KVStore
	txn := sde.Store.Begin()
	txnID := txn.ID()

	// 2. Apply Strict Two-Phase Locking (2PL) mutations if a LockManager is active
	if sde.LockMgr != nil {
		if err := sde.LockMgr.Acquire(txnID, worldStateKey, ultimate_db.LockExclusive); err != nil {
			txn.Abort()
			return fmt.Errorf("concurrency control lock acquisition failed for world state key: %w", err)
		}
		if err := sde.LockMgr.Acquire(txnID, ledgerKey, ultimate_db.LockExclusive); err != nil {
			sde.LockMgr.ReleaseAll(txnID)
			txn.Abort()
			return fmt.Errorf("concurrency control lock acquisition failed for ledger key: %w", err)
		}
		defer sde.LockMgr.ReleaseAll(txnID)
	}

	// 3. Persist modifications down to abstract storage layer structures
	if err := sde.Store.Put(txn, []byte(worldStateKey), worldStateBytes, lifespan); err != nil {
		txn.Abort()
		return fmt.Errorf("failed committing execution world state mutation frame: %w", err)
	}

	if err := sde.Store.Put(txn, []byte(ledgerKey), ledgerBytes, lifespan); err != nil {
		txn.Abort()
		return fmt.Errorf("failed appending transaction ledger track record: %w", err)
	}

	// 4. Seal snapshot states
	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to commit isolated KV transaction block: %w", err)
	}

	return nil
}

func computeStateHash(payload map[string]interface{}) (string, error) {
	orderedBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(orderedBytes)
	return hex.EncodeToString(hash[:]), nil
}

func generateRandomJTI() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// =============================================================================
// Hardened Dynamic Recursive Grammatical Parser Core
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
		maxDepth: 25, 
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
	// Short-circuit immediately if we are already unwinding from an error
	if len(p.errs) > 0 {
		return nil
	}

	p.depth++
	defer func() { p.depth-- }()

	if p.depth > p.maxDepth {
		p.errs = append(p.errs, "maximum parsing nesting expression limit exceeded")
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
				arg := p.parseExpr()
				// Abort and unwind the loop instantly if a child call failed or hit the depth ceiling
				if len(p.errs) > 0 {
					return nil
				}
				if arg != nil {
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
