package router_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common/ja4db"
	"github.com/ImAubrey/acore/common/platform"
	"github.com/ImAubrey/acore/common/session"
)

func TestRoutingRuleJA4DatabaseAttribute(t *testing.T) {
	assetDir := t.TempDir()
	raw := []byte("t13d1516h2_8daaf6152771_e5627efa2ab1,malware\n")
	bin, err := ja4db.Compile(raw)
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4.db"), bin, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}
	t.Setenv(platform.AssetLocation, assetDir)

	rule := &RoutingRule{
		Attributes: map[string]string{
			"ja4": EncodeJA4DBAttributeValue("ja4.db", "malware"),
		},
	}
	cond, err := rule.BuildCondition()
	if err != nil {
		t.Fatalf("BuildCondition returned error: %v", err)
	}

	content := &session.Content{
		Attributes: map[string]string{
			"ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
		},
	}
	match := cond.Apply(withContent(content))
	if !match {
		t.Fatal("expected ja4 database matcher to match")
	}
	if got := content.Attribute("ja4_tag"); got != "malware" {
		t.Fatalf("expected ja4_tag to be set, got %q", got)
	}

	mismatch := cond.Apply(withContent(&session.Content{
		Attributes: map[string]string{
			"ja4": "t12i1212h1_aaaaaaaaaaaa_bbbbbbbbbbbb",
		},
	}))
	if mismatch {
		t.Fatal("expected ja4 database matcher to not match")
	}
}

func TestRoutingRuleJA4CustomDatabaseAttributeUsesRawTag(t *testing.T) {
	assetDir := t.TempDir()
	raw := []byte("t13d1516h2_8daaf6152771_e5627efa2ab1,malware\n")
	bin, err := ja4db.Compile(raw)
	if err != nil {
		t.Fatalf("compile ja4 custom db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4_custom.db"), bin, 0o644); err != nil {
		t.Fatalf("write ja4 custom db: %v", err)
	}
	t.Setenv(platform.AssetLocation, assetDir)

	rule := &RoutingRule{
		Attributes: map[string]string{
			"ja4": EncodeJA4DBAttributeValue("ja4_custom.db", "malware"),
		},
	}
	cond, err := rule.BuildCondition()
	if err != nil {
		t.Fatalf("BuildCondition returned error: %v", err)
	}

	content := &session.Content{
		Attributes: map[string]string{
			"ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
		},
	}
	if !cond.Apply(withContent(content)) {
		t.Fatal("expected ja4 custom matcher to match")
	}
	if got := content.Attribute("ja4_tag"); got != "malware" {
		t.Fatalf("expected malware, got %q", got)
	}
}

func TestRoutingRuleJA4CustomDatabaseAttributeKeepsStructuredTag(t *testing.T) {
	assetDir := t.TempDir()
	raw := []byte("t13d1516h2_8daaf6152771_e5627efa2ab1,ua:family:chromium-597\n")
	bin, err := ja4db.Compile(raw)
	if err != nil {
		t.Fatalf("compile ja4 custom db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4_custom.db"), bin, 0o644); err != nil {
		t.Fatalf("write ja4 custom db: %v", err)
	}
	t.Setenv(platform.AssetLocation, assetDir)

	rule := &RoutingRule{
		Attributes: map[string]string{
			"ja4": EncodeJA4DBAttributeValue("ja4_custom.db", "ua:family:chromium-597"),
		},
	}
	cond, err := rule.BuildCondition()
	if err != nil {
		t.Fatalf("BuildCondition returned error: %v", err)
	}

	content := &session.Content{
		Attributes: map[string]string{
			"ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
		},
	}
	if !cond.Apply(withContent(content)) {
		t.Fatal("expected ja4 custom matcher to match")
	}
	if got := content.Attribute("ja4_tag"); got != "ua:family:chromium-597" {
		t.Fatalf("expected ua:family:chromium-597, got %q", got)
	}
}

func TestRoutingRuleJA4DatabaseAttributeReloadsAfterDBUpdate(t *testing.T) {
	assetDir := t.TempDir()
	dbPath := filepath.Join(assetDir, "ja4.db")

	writeDB := func(content []byte) {
		bin, err := ja4db.Compile(content)
		if err != nil {
			t.Fatalf("compile ja4 db: %v", err)
		}
		if err := os.WriteFile(dbPath, bin, 0o644); err != nil {
			t.Fatalf("write ja4 db: %v", err)
		}
	}

	writeDB([]byte("t13d1516h2_8daaf6152771_e5627efa2ab1,malware\n"))
	t.Setenv(platform.AssetLocation, assetDir)

	rule := &RoutingRule{
		Attributes: map[string]string{
			"ja4": EncodeJA4DBAttributeValue("ja4.db", "malware"),
		},
	}
	cond1, err := rule.BuildCondition()
	if err != nil {
		t.Fatalf("BuildCondition returned error: %v", err)
	}
	if !cond1.Apply(withContent(&session.Content{
		Attributes: map[string]string{"ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"},
	})) {
		t.Fatal("expected first matcher to match original fingerprint")
	}

	// Ensure file signature changes on filesystems with coarse timestamp resolution.
	time.Sleep(20 * time.Millisecond)
	writeDB([]byte("t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb,malware\n"))

	cond2, err := rule.BuildCondition()
	if err != nil {
		t.Fatalf("BuildCondition after update returned error: %v", err)
	}
	if !cond2.Apply(withContent(&session.Content{
		Attributes: map[string]string{"ja4": "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"},
	})) {
		t.Fatal("expected matcher to load updated database")
	}
}

func TestRoutingRuleJA4DatabaseAttributeWindowsPathAndColonTag(t *testing.T) {
	assetDir := t.TempDir()
	dbPath := filepath.Join(assetDir, "ja4.db")
	raw := []byte("t13d1516h2_8daaf6152771_e5627efa2ab1,source:ja4db\n")
	bin, err := ja4db.Compile(raw)
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(dbPath, bin, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}

	rule := &RoutingRule{
		Attributes: map[string]string{
			"ja4": EncodeJA4DBAttributeValue(dbPath, "source:ja4db"),
		},
	}
	cond, err := rule.BuildCondition()
	if err != nil {
		t.Fatalf("BuildCondition returned error: %v", err)
	}
	if !cond.Apply(withContent(&session.Content{
		Attributes: map[string]string{
			"ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
		},
	})) {
		t.Fatal("expected ja4 database matcher to match colon tag")
	}
}

func TestRoutingRuleJA4AttributeDirectFingerprintMatch(t *testing.T) {
	const fp = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	const other = "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"

	rule := &RoutingRule{
		Attributes: map[string]string{
			"ja4": fp,
		},
	}
	cond, err := rule.BuildCondition()
	if err != nil {
		t.Fatalf("BuildCondition returned error: %v", err)
	}

	content := &session.Content{
		Attributes: map[string]string{"ja4": fp},
	}
	if !cond.Apply(withContent(content)) {
		t.Fatal("expected direct ja4 fingerprint matcher to match")
	}
	if got := content.Attribute("ja4_tag"); got != "" {
		t.Fatalf("expected no ja4_tag for direct fingerprint matcher, got %q", got)
	}

	if cond.Apply(withContent(&session.Content{
		Attributes: map[string]string{"ja4": other},
	})) {
		t.Fatal("expected direct ja4 fingerprint matcher to reject non-matching fingerprint")
	}
}

func TestRoutingRuleJA4DatabaseAttributeUnlabeledInLibrary(t *testing.T) {
	assetDir := t.TempDir()
	unlabeled := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	labeled := "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
	raw := []byte(unlabeled + "\n" + labeled + ",client:browser:chromium\n")
	bin, err := ja4db.Compile(raw)
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "ja4.db"), bin, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}
	t.Setenv(platform.AssetLocation, assetDir)

	rule := &RoutingRule{
		Attributes: map[string]string{
			"ja4": EncodeJA4DBAttributeValue("ja4.db", "!"),
		},
	}
	cond, err := rule.BuildCondition()
	if err != nil {
		t.Fatalf("BuildCondition returned error: %v", err)
	}

	content := &session.Content{
		Attributes: map[string]string{"ja4": unlabeled},
	}
	if !cond.Apply(withContent(content)) {
		t.Fatal("expected unlabeled in-library fingerprint to match ja4:!")
	}
	if got := content.Attribute("ja4_tag"); got != "" {
		t.Fatalf("expected no ja4_tag for unlabeled matcher, got %q", got)
	}

	if cond.Apply(withContent(&session.Content{
		Attributes: map[string]string{"ja4": labeled},
	})) {
		t.Fatal("expected labeled in-library fingerprint to not match ja4:!")
	}
}
