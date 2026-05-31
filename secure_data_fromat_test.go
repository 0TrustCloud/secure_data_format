package secure_data_format

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0TrustCloud/ultimate_db"
	"github.com/golang-jwt/jwt/v5"
)

// =============================================================================
// Memory Mock Layer for Interface Isolation
// =============================================================================

type mockTxnHandle struct {
	id        uint64
	committed bool
	aborted   bool
}

func (m *mockTxnHandle) ID() uint64    { return m.id }
func (m *mockTxnHandle) Commit() error { m.committed = true; return nil }
func (m *mockTxnHandle) Abort() error  { m.aborted = true; return nil }

type mockKVStore struct {
	records map[string][]byte
	nextID  uint64
}

func (m *mockKVStore) Begin() ultimate_db.TxnHandle {
	m.nextID++
	return &mockTxnHandle{id: m.nextID}
}

func (m *mockKVStore) Get(txn ultimate_db.TxnHandle, key []byte) ([]byte, error) {
	if val, ok := m.records[string(key)]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockKVStore) Put(txn ultimate_db.TxnHandle, key []byte, value []byte, ttl time.Duration) error {
	m.records[string(key)] = value
	return nil
}

func (m *mockKVStore) Delete(txn ultimate_db.TxnHandle, key []byte) error {
	delete(m.records, string(key))
	return nil
}

func (m *mockKVStore) NewIterator(txn ultimate_db.TxnHandle, prefix []byte) ultimate_db.KVIterator {
	return nil
}

type mockLockManager struct {
	acquiredLocks map[string]uint64
	releasedAll   bool
}

func (m *mockLockManager) Acquire(txnID uint64, key string, mode ultimate_db.LockMode) error {
	m.acquiredLocks[key] = txnID
	return nil
}

func (m *mockLockManager) Release(txnID uint64, key string) error {
	delete(m.acquiredLocks, key)
	return nil
}

func (m *mockLockManager) ReleaseAll(txnID uint64) error {
	m.releasedAll = true
	return nil
}

// Helper function to generate a valid RSA key pair for cryptographic token signing
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test RSA private key: %v", err)
	}
	return privKey
}

// =============================================================================
// Test Suites
// =============================================================================

func TestCompileSecureData_StructuredLog(t *testing.T) {
	privKey := generateTestRSAKey(t)
	storeMock := &mockKVStore{records: make(map[string][]byte)}
	lockMock := &mockLockManager{acquiredLocks: make(map[string]uint64)}

	engine, err := New(storeMock, lockMock, "test-issuer", privKey)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	script := `
		log:system.error(
			message("Database connection pool exhausted")
			severity("CRITICAL")
			component("auth-broker")
		)
	`

	tx := DataInvocation{
		TargetAddress: "cluster-us-east-logs",
		Caller:        "auth-service-pod-3",
		Nonce:         10442,
		Method:        "EMIT",
		Profile:       ProfileStructuredLog,
		Args: map[string]interface{}{
			"environment": "production",
		},
	}

	tokenStr, err := engine.CompileSecureData(script, tx)
	if err != nil {
		t.Fatalf("expected successful log token compilation, got error: %v", err)
	}

	parsedToken, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return &privKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse generated token: %v", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		t.Fatalf("token is invalid or corrupted")
	}

	if claims["iss"] != "test-issuer" {
		t.Errorf("expected issuer 'test-issuer', got %v", claims["iss"])
	}
	if claims["profile_type"] != string(ProfileStructuredLog) {
		t.Errorf("expected profile type 'LOG', got %v", claims["profile_type"])
	}
	if claims["target_address"] != "cluster-us-east-logs" {
		t.Errorf("expected target address 'cluster-us-east-logs', got %v", claims["target_address"])
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("expiration claim missing or invalid")
	}
	expectedMinExp := time.Now().Add(87500 * time.Hour).Unix()
	if int64(exp) < expectedMinExp {
		t.Errorf("log token expiration window is too short")
	}
}

func TestCompileSecureData_GrantAccess(t *testing.T) {
	privKey := generateTestRSAKey(t)
	storeMock := &mockKVStore{records: make(map[string][]byte)}
	lockMock := &mockLockManager{acquiredLocks: make(map[string]uint64)}

	engine, err := New(storeMock, lockMock, "test-issuer", privKey)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	script := `
		grant:resource.access#vault-alpha(
			scope("read")
			conditions:mfa.required("true")
		)
	`

	tx := DataInvocation{
		TargetAddress: "vault-manager-service",
		Caller:        "user-gregory-disney",
		Nonce:         401,
		Method:        "DELEGATE",
		Profile:       ProfileGrant,
		Args:          map[string]interface{}{},
	}

	tokenStr, err := engine.CompileSecureData(script, tx)
	if err != nil {
		t.Fatalf("expected successful grant token compilation, got error: %v", err)
	}

	parsedToken, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return &privKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse generated token: %v", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		t.Fatalf("token is invalid")
	}

	if claims["profile_type"] != string(ProfileGrant) {
		t.Errorf("expected profile type 'GRANT', got %v", claims["profile_type"])
	}

	stateUpdates, ok := claims["state_updates"].(map[string]interface{})
	if !ok {
		t.Fatalf("state_updates claim block is missing or invalid")
	}

	// Fixed: The custom parser keys this block by the core tag name "grant"
	grantBlock, ok := stateUpdates["grant"].(map[string]interface{})
	if !ok {
		t.Fatalf("compiled OpenGraph grant structural payload block is missing")
	}

	if grantBlock["id"] != "vault-alpha" {
		t.Errorf("expected resource id 'vault-alpha', got %v", grantBlock["id"])
	}
}

func TestCompileSecureData_ProofOfPossession(t *testing.T) {
	privKey := generateTestRSAKey(t)
	storeMock := &mockKVStore{records: make(map[string][]byte)}
	lockMock := &mockLockManager{acquiredLocks: make(map[string]uint64)}

	engine, err := New(storeMock, lockMock, "test-issuer", privKey)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	script := `
		device:binding.hardware(
			challenge("b7a9f2e30c1d4e5f")
		)
	`

	tx := DataInvocation{
		TargetAddress: "device-macbook-pro-serial-9921",
		Caller:        "secure-enclave-agent",
		Nonce:         87,
		Method:        "ASSERT",
		Profile:       ProfileProofOfPoss,
		Args:          map[string]interface{}{},
	}

	tokenStr, err := engine.CompileSecureData(script, tx)
	if err != nil {
		t.Fatalf("expected successful PoP token compilation, got error: %v", err)
	}

	parsedToken, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return &privKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse generated token: %v", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		t.Fatalf("token is invalid")
	}

	if claims["profile_type"] != string(ProfileProofOfPoss) {
		t.Errorf("expected profile type 'POP', got %v", claims["profile_type"])
	}

	exp := int64(claims["exp"].(float64))
	maxExpectedExp := time.Now().Add(6 * time.Minute).Unix()
	if exp > maxExpectedExp {
		t.Errorf("PoP token expiration window exceeds the secure ephemeral ceiling limit")
	}
}

func TestCompileSecureData_ParserLimitsAndErrors(t *testing.T) {
	privKey := generateTestRSAKey(t)
	storeMock := &mockKVStore{records: make(map[string][]byte)}
	lockMock := &mockLockManager{acquiredLocks: make(map[string]uint64)}

	engine, err := New(storeMock, lockMock, "test-issuer", privKey)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	tx := DataInvocation{
		TargetAddress: "test-boundary",
		Caller:        "test-runner",
		Nonce:         1,
		Method:        "TEST",
		Profile:       ProfileGrant,
		Args:          map[string]interface{}{},
	}

	malformedScript := `grant:access(value("missing-bracket`
	_, err = engine.CompileSecureData(malformedScript, tx)
	if err == nil {
		t.Error("expected syntax errors to reject compilation, but operation reported success")
	}

	deeplyNestedScript := ""
	for i := 0; i < 30; i++ {
		deeplyNestedScript += "nested:block("
	}
	deeplyNestedScript += `"value"`
	for i := 0; i < 30; i++ {
		deeplyNestedScript += ")"
	}

	_, err = engine.CompileSecureData(deeplyNestedScript, tx)
	if err == nil {
		t.Error("expected deep recursion sequence stack to be truncated and aborted, but reported success")
	} else if !strings.Contains(err.Error(), "maximum parsing nesting expression limit exceeded") {
		t.Errorf("unexpected error message signature returned: %v", err)
	}
}

func TestDeterministicStateHash(t *testing.T) {
	payloadA := map[string]interface{}{
		"a": "value_a",
		"b": "value_b",
	}
	payloadB := map[string]interface{}{
		"b": "value_b",
		"a": "value_a",
	}

	hashA, errA := computeStateHash(payloadA)
	hashB, errB := computeStateHash(payloadB)

	if errA != nil || errB != nil {
		t.Fatalf("failed computing test payload state hashes: %v / %v", errA, errB)
	}

	if hashA != hashB {
		t.Errorf("canonical state execution serialization is non-deterministic: hashA %s != hashB %s", hashA, hashB)
	}
}
