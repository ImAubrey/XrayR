package ja4db

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCompileCSVAndReadTag(t *testing.T) {
	raw := []byte("" +
		"# fingerprint,tags...\n" +
		"t13d1516h2_8daaf6152771_e5627efa2ab1,malware,botnet\n" +
		"t12i1212h1_aaaaaaaaaaaa_bbbbbbbbbbbb,benign\n")

	bin, err := Compile(raw)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	if !IsBinary(bin) {
		t.Fatal("expected binary output")
	}

	path := filepath.Join(t.TempDir(), "ja4.db")
	if err := os.WriteFile(path, bin, 0o644); err != nil {
		t.Fatalf("write db file: %v", err)
	}

	got, err := ReadTagValues(path, "malware")
	if err != nil {
		t.Fatalf("ReadTagValues returned error: %v", err)
	}
	want := []string{"t13d1516h2_8daaf6152771_e5627efa2ab1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected malware values: got=%v want=%v", got, want)
	}
}

func TestCompileJSONObjectTagMap(t *testing.T) {
	raw := []byte(`{
		"malware": ["t13d1516h2_8daaf6152771_e5627efa2ab1"],
		"benign": ["t12i1212h1_aaaaaaaaaaaa_bbbbbbbbbbbb"]
	}`)
	bin, err := Compile(raw)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	if !IsBinary(bin) {
		t.Fatal("expected binary output")
	}

	values, err := CollectTag(bin, "benign")
	if err != nil {
		t.Fatalf("CollectTag returned error: %v", err)
	}
	want := []string{"t12i1212h1_aaaaaaaaaaaa_bbbbbbbbbbbb"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("unexpected benign values: got=%v want=%v", values, want)
	}
}

func TestCollectTagTextNotFound(t *testing.T) {
	raw := []byte("t13d1516h2_8daaf6152771_e5627efa2ab1,malware\n")
	if _, err := CollectTag(raw, "unknown"); err == nil {
		t.Fatal("expected error when tag not found")
	}
}

func TestPrepareForSubscriptionAutoRequiresBinary(t *testing.T) {
	raw := []byte(`{"malware":["t13d1516h2_8daaf6152771_e5627efa2ab1"]}`)
	if _, err := PrepareForSubscription(raw, ""); err == nil {
		t.Fatal("expected auto mode to reject non-binary payload")
	}
}

func TestPrepareForSubscriptionJSONUnsupported(t *testing.T) {
	bin, err := Compile([]byte("t13d1516h2_8daaf6152771_e5627efa2ab1,malware\n"))
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	if _, err := PrepareForSubscription(bin, "json"); err == nil {
		t.Fatal("expected json mode to be unsupported")
	}
}

func TestPrepareForSubscriptionDBMode(t *testing.T) {
	bin, err := Compile([]byte("t13d1516h2_8daaf6152771_e5627efa2ab1,malware\n"))
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}

	got, err := PrepareForSubscription(bin, "db")
	if err != nil {
		t.Fatalf("PrepareForSubscription(db) returned error: %v", err)
	}
	if !IsBinary(got) {
		t.Fatal("expected binary payload in db mode")
	}

	if _, err := PrepareForSubscription([]byte("t13d1516h2_8daaf6152771_e5627efa2ab1,malware\n"), "db"); err == nil {
		t.Fatal("expected db mode to reject non-binary payload")
	}

	gotAuto, err := PrepareForSubscription(bin, "")
	if err != nil {
		t.Fatalf("PrepareForSubscription(auto) returned error: %v", err)
	}
	if !IsBinary(gotAuto) {
		t.Fatal("expected binary payload in auto mode")
	}
}
