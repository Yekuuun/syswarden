package event

import (
	"bytes"
	"embed"
	"testing"
	"time"
)

//go:embed testdata/*
var goldenFixtures embed.FS

var wall = time.Date(2026, 11, 12, 18, 30, 0, 123456789, time.UTC)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := goldenFixtures.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRecordGolden(t *testing.T) {
	cases := map[string][]byte{
		"conn_open_v4.json":   connV4Record(TypeConnOpen, 2, 1, DirActive),
		"conn_close_v4.json":  connV4Record(TypeConnClose, 4, 7, DirUnknown),
		"lsm_connect_v6.json": sockV6Record(TypeLSMConnect),
		"lsm_bind_v6.json":    sockV6Record(TypeLSMBind),
	}
	for name, record := range cases {
		t.Run(name, func(t *testing.T) {
			ev, err := Decode(record)
			if err != nil {
				t.Fatal(err)
			}
			rec, err := NewRecord(ev, wall)
			if err != nil {
				t.Fatal(err)
			}
			line, err := Encode(rec)
			if err != nil {
				t.Fatal(err)
			}
			if want := fixture(t, name); !bytes.Equal(line, want) {
				t.Fatalf("json changed\n got: %s\nwant: %s", line, want)
			}
		})
	}
}

func TestCommString(t *testing.T) {
	var full [16]byte
	copy(full[:], "0123456789abcdef")
	cases := map[string]struct {
		comm [16]byte
		want string
	}{
		"nul terminated": {[16]byte{'s', 's', 'h', 0, 'x'}, "ssh"},
		"full width":     {full, "0123456789abcdef"},
		"empty":          {[16]byte{}, ""},
	}
	for name, tc := range cases {
		if got := commString(tc.comm); got != tc.want {
			t.Fatalf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

func TestUnknownValuesStayStrings(t *testing.T) {
	if protoName(250) != "250" || sockTypeName(9) != "9" || tcpStateName(42) != "42" || tcpStateName(0) != "0" {
		t.Fatal("unknown values must fall back to their decimal string")
	}
}

func TestDirectionOnlyWhenKnown(t *testing.T) {
	cases := map[string]struct {
		record []byte
		want   string
	}{
		"open active":         {connV4Record(TypeConnOpen, 2, 1, DirActive), "active"},
		"open passive":        {connV4Record(TypeConnOpen, 3, 1, DirPassive), "passive"},
		"failed connect":      {connV4Record(TypeConnClose, 2, 7, DirActive), "active"},
		"close from FIN_WAIT": {connV4Record(TypeConnClose, 4, 7, DirUnknown), ""},
	}
	for name, tc := range cases {
		ev, err := Decode(tc.record)
		if err != nil {
			t.Fatal(err)
		}
		rec, _ := NewRecord(ev, wall)
		if rec.Direction != tc.want {
			t.Fatalf("%s: direction %q, want %q", name, rec.Direction, tc.want)
		}
	}
}
