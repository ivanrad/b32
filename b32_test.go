package b32

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

var testVectors = []struct {
	in         uint64
	b32encoded []byte
}{
	// adapted rfc4648 test vectors
	{0x00_00_00_00_00_00_00_00, []byte("aaaaaaaaaaaaa")}, /* "" */
	{0x66_00_00_00_00_00_00_00, []byte("myaaaaaaaaaaa")}, /* "f" */
	{0x66_6f_00_00_00_00_00_00, []byte("mzxqaaaaaaaaa")}, /* "fo" */
	{0x66_6f_6f_00_00_00_00_00, []byte("mzxw6aaaaaaaa")}, /* "foo" */
	{0x66_6f_6f_62_00_00_00_00, []byte("mzxw6yqaaaaaa")}, /* "foob" */
	{0x66_6f_6f_62_61_00_00_00, []byte("mzxw6ytbaaaaa")}, /* "fooba" */
	{0x66_6f_6f_62_61_72_00_00, []byte("mzxw6ytboiaaa")}, /* "foobar" */
	// test vectors adapted from go stdlib (Wikipedia examples)
	{0x73_75_72_65_2e_00_00_00, []byte("on2xezjoaaaaa")}, /* "sure." */
	{0x73_75_72_65_00_00_00_00, []byte("on2xeziaaaaaa")}, /* "sure" */
	{0x73_75_72_00_00_00_00_00, []byte("on2xeaaaaaaaa")}, /* "sur" */
	{0x73_75_00_00_00_00_00_00, []byte("on2qaaaaaaaaa")}, /* "su" */
	{0x6c_65_61_73_75_72_65_2e, []byte("nrswc43vojss4")}, /* "leasure." */
	{0x65_61_73_75_72_65_2e_00, []byte("mvqxg5lsmuxaa")}, /* "easure." */
	{0x61_73_75_72_65_2e_00_00, []byte("mfzxk4tffyaaa")}, /* "asure." */
	// some more test vectors
	{0xff_ff_ff_ff_ff_ff_ff_ff, []byte("7777777777776")},
	{0xff_ff_ff_ff_ff_ff_ff_fe, []byte("7777777777774")},
	{0x01_ff_ff_ff_ff_ff_ff_fa, []byte("ah7777777777u")},
	{0x01_02_03_04_05_06_07_08, []byte("aebagbafaydqq")},
	{0x12_34_56_78_9a_bc_cd_ef, []byte("ci2fm6e2xtg66")},
	{0x88_77_66_55_44_33_22_11, []byte("rb3wmvkegmrbc")},
}

func TestAlphabetLength(t *testing.T) {
	t.Parallel()

	want := 1 << 5
	got := len(encMap)
	if got != want {
		t.Errorf("invalid b32 alphabet length; expected %v; got %v", want, got)
	}
}

func TestAlphabetUnique(t *testing.T) {
	t.Parallel()

	var m [256]bool
	for _, c := range encMap {
		if m[c] {
			t.Errorf("invalid b32 alphabet; duplicate symbol: %q", c)
		}
		m[c] = true
	}
}

func TestEncode(t *testing.T) {
	t.Parallel()

	for _, tc := range testVectors {
		t.Run(fmt.Sprintf("{%#.16x,%q}", tc.in, tc.b32encoded), func(t *testing.T) {
			t.Parallel()

			var b32enc [13]byte
			EncodeUint64(tc.in, b32enc[:])
			if !bytes.Equal(tc.b32encoded, b32enc[:]) {
				t.Errorf("error while encoding %#.16x; expected %q; got %q", tc.in, tc.b32encoded, b32enc)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	t.Parallel()

	for _, tc := range testVectors {
		t.Run(fmt.Sprintf("{%#.16x,%q}", tc.in, tc.b32encoded), func(t *testing.T) {
			t.Parallel()

			d, ok := DecodeUint64(tc.b32encoded)
			if !ok {
				t.Errorf("error while decoding %q", tc.b32encoded)
			}
			if d != tc.in {
				t.Errorf("error while decoding %q; expected %#.16x; got %#.16x", tc.b32encoded, tc.in, d)
			}
		})
	}
}

func TestEncodeToString(t *testing.T) {
	t.Parallel()

	for _, tc := range testVectors {
		t.Run(fmt.Sprintf("{%#.16x,%q}", tc.in, tc.b32encoded), func(t *testing.T) {
			t.Parallel()

			b32enc := EncodeUint64ToString(tc.in)
			if strings.Compare(string(tc.b32encoded), b32enc) != 0 {
				t.Errorf("error while encoding %#.16x; expected %q; got %q", tc.in, tc.b32encoded, b32enc)
			}
		})
	}
}

func TestDecodeFromString(t *testing.T) {
	t.Parallel()

	for _, tc := range testVectors {
		t.Run(fmt.Sprintf("{%#.16x,%q}", tc.in, tc.b32encoded), func(t *testing.T) {
			t.Parallel()

			d, ok := DecodeUint64FromString(string(tc.b32encoded))
			if !ok {
				t.Errorf("error while decoding %q", tc.b32encoded)
			}
			if d != tc.in {
				t.Errorf("error while decoding %q; expected %#.16x; got %#.16x", tc.b32encoded, tc.in, d)
			}
		})
	}
}

func TestDecodeCorruptInput(t *testing.T) {
	t.Parallel()

	corruptInput := []string{
		"1234567890123", "caazbaywxamm1", "aaaaaaaaaaa8a",
		"kbezvysgla9au", "cmyzzwaxy0aaa", "rb9wmvkegmrbc",
	}

	for _, in := range corruptInput {
		_, ok := DecodeUint64FromString(in)
		if ok {
			t.Errorf("error: undetected corrupt base32 encoding %q", in)
		}
	}
}

func TestMatchStdlibEncoder(t *testing.T) {
	t.Parallel()

	for _, tc := range testVectors {
		t.Run(fmt.Sprintf("{%#.16x,%q}", tc.in, tc.b32encoded), func(t *testing.T) {
			t.Parallel()

			var b32stdlib, b32enc [13]byte
			stdlibEncode(tc.in, b32stdlib[:])
			EncodeUint64(tc.in, b32enc[:])
			if !bytes.Equal(b32stdlib[:], b32enc[:]) {
				t.Errorf("error while encoding %#.16x; expected %q; got %q", tc.in, b32stdlib, b32enc)
			}
		})
	}
}

func TestMatchStdlibDecoder(t *testing.T) {
	t.Parallel()

	for _, tc := range testVectors {
		t.Run(fmt.Sprintf("{%#.16x,%q}", tc.in, tc.b32encoded), func(t *testing.T) {
			t.Parallel()

			dstd, err := stdlibDecode(tc.b32encoded)
			d, ok := DecodeUint64(tc.b32encoded)
			if err != nil || !ok {
				t.Errorf("error while decoding %q", tc.b32encoded)
			}
			if dstd != d {
				t.Errorf("error while decoding %q; expected %#.16x; got %#.16x", tc.b32encoded, dstd, d)
			}
		})
	}
}

// RFC 4648 32-char alphabet; lowercase, no-padding.
var stdlibEncoding = base32.NewEncoding(StdEncoding).WithPadding(base32.NoPadding)

func stdlibEncode(n uint64, dst []byte) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], n)
	stdlibEncoding.Encode(dst, buf[:])
}

func stdlibDecode(src []byte) (uint64, error) {
	var buf [8]byte
	_, err := stdlibEncoding.Decode(buf[:], src)

	return binary.BigEndian.Uint64(buf[:]), err
}

func BenchmarkEncode(b *testing.B) {
	for _, tc := range testVectors {
		b.Run(fmt.Sprintf("{%#.16x,%q}", tc.in, tc.b32encoded), func(b *testing.B) {
			var b32enc [13]byte
			for range b.N {
				EncodeUint64(tc.in, b32enc[:])
			}
		})
	}
}

func BenchmarkDecode(b *testing.B) {
	for _, tc := range testVectors {
		b.Run(fmt.Sprintf("{%#.16x,%q}", tc.in, tc.b32encoded), func(b *testing.B) {
			for range b.N {
				_, _ = DecodeUint64(tc.b32encoded)
			}
		})
	}
}

func FuzzEncodeDecode(f *testing.F) {
	seedFuzzTest(f)

	f.Fuzz(func(t *testing.T, n uint64) {
		t.Helper()

		var b32enc [13]byte
		EncodeUint64(n, b32enc[:])
		d, ok := DecodeUint64(b32enc[:])
		if !ok {
			t.Fatalf("error while decoding: %q", b32enc)
		}
		if d != n {
			t.Fatalf("error while decoding; expected %#.16x; got %#.16x", n, d)
		}
	})
}

func FuzzEncodeDecodeMatchStdlib(f *testing.F) {
	seedFuzzTest(f)

	f.Fuzz(func(t *testing.T, n uint64) {
		t.Helper()

		var b32std, b32enc [13]byte
		stdlibEncode(n, b32std[:])
		EncodeUint64(n, b32enc[:])
		if !bytes.Equal(b32std[:], b32enc[:]) {
			t.Fatalf("error while encoding %#.16x; expected %q; got %q", n, b32std, b32enc)
		}
		d, ok := DecodeUint64(b32enc[:])
		if !ok {
			t.Fatalf("error while decoding: %q", b32enc)
		}
		if d != n {
			t.Fatalf("error while decoding; expected %#.16x; got %#.16x", n, d)
		}
	})
}

func seedFuzzTest(f *testing.F) {
	f.Helper()
	for _, tc := range testVectors {
		f.Add(tc.in)
	}
}
