package router

import "testing"

func TestJA4DBAttributeValueRoundTrip(t *testing.T) {
	file := "ja4.db"
	tag := "malware"
	value := EncodeJA4DBAttributeValue(file, tag)

	gotFile, gotTag, ok := DecodeJA4DBAttributeValue(value)
	if !ok {
		t.Fatalf("DecodeJA4DBAttributeValue() failed for %q", value)
	}
	if gotFile != file {
		t.Fatalf("unexpected file: got=%q want=%q", gotFile, file)
	}
	if gotTag != tag {
		t.Fatalf("unexpected tag: got=%q want=%q", gotTag, tag)
	}
}

func TestJA4DBAttributeValueRoundTripWindowsPathAndColonTag(t *testing.T) {
	file := `D:\Goland\Acore\.tmp\ja4_curated.db`
	tag := "source:ja4db"
	value := EncodeJA4DBAttributeValue(file, tag)

	gotFile, gotTag, ok := DecodeJA4DBAttributeValue(value)
	if !ok {
		t.Fatalf("DecodeJA4DBAttributeValue() failed for %q", value)
	}
	if gotFile != file {
		t.Fatalf("unexpected file: got=%q want=%q", gotFile, file)
	}
	if gotTag != tag {
		t.Fatalf("unexpected tag: got=%q want=%q", gotTag, tag)
	}
}

func TestDecodeLegacyJA4DBAttributeValue(t *testing.T) {
	legacy := "acore.internal.ja4db:ja4.db:malware"
	gotFile, gotTag, ok := DecodeJA4DBAttributeValue(legacy)
	if !ok {
		t.Fatalf("DecodeJA4DBAttributeValue() failed for legacy value %q", legacy)
	}
	if gotFile != "ja4.db" || gotTag != "malware" {
		t.Fatalf("unexpected decode: file=%q tag=%q", gotFile, gotTag)
	}
}
