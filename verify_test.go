package c3

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

// Note: dont call a test function TestMain! that name is sort of reserved for a setup/teardown init-like function

// --- Some test certs ---

const TEST_ROOT6_PUB = `
--------------------------[ root6 - Cert chain ]----------------------------
2Q63AekZswEJAFcJABABivPsRT1L5jn0eLSKIOvoGQEFcm9vdDY5AgEDCQMgZqEqy8oU+2nOHBHG
PoTMdGtPFXfCs/7gOhE0byS1T0SpBAQYCtAfqQUEAwrOHxkGBHJvb3QJAVYJAEDESNovSXa+uPLw
vHirVobj5DccvPh2F3EIC7vxABXlwdRNHJsCsin/COzxmRy/C2lZ50ZXIe4sqhdbNgkPGvACCQEQ
AYrz7EU9S+Y59Hi0iiDr6A==
`

func TestNilBlock(t *testing.T) {
	_, _, err := LoadPubBlock(nil)
	require.Error(t, err, "buffer is empty")
}

func TestZeroSizeBlock(t *testing.T) {
	var block []byte
	_, _, err := LoadPubBlock(block)
	require.Error(t, err, "buffer is empty")
}

func TestBlockOfZeroes(t *testing.T) {
	block := make([]byte, 64)
	_, _, err := LoadPubBlock(block)
	require.Error(t, err, "incorrect type of key in header")
}

// b3.SetStrictDecode(true) // dont allow incoming nulls in cert chain messages
// Policy: After all that, we can't actually do this, because sometimes python c3
//         generates nil fields. Us mapping them to zero-values is actually the correct thing to do.

func TestVerifyNoTrusted(t *testing.T) {
	var chain []DasCertPayload
	var ppkey int
	var err error
	var block []byte
	var lines []string

	block, lines, err = TextToBinaryBlock(TEST_ROOT6_PUB)
	require.Nil(t, err)
	ppkey, chain, err = LoadPubBlock(block)
	require.Nil(t, err)
	require.Equal(t, PUB_CERTCHAIN, ppkey)
	_ = lines // Note: ignoring text lines currently.

	err = Verify(chain)
	// Note: err should be "chain does not link to trusted certs"
	require.Error(t, err, "'chain not trust linked'")
	require.Contains(t, err.Error(), "does not link to trusted", "chain not trust linked")
}

func TestVerifyTrustedAdded(t *testing.T) {
	// var chain []DasCertPayload
	// var ppkey int
	var err error
	var block []byte
	var lines []string
	block, lines, err = TextToBinaryBlock(TEST_ROOT6_PUB)
	_ = lines // note: ignoring lines for now.
	require.Nil(t, err)
	err = AddTrusted(block)
	require.Nil(t, err)
}

// ---------------------------------------------------------------------------------------------------------------------
// - Longer chains and payloads.

const TEST_PAYLOAD9 = `
--------------------------------[ Payload ]---------------------------------
2QylAukZbwkAJFRoaXMgaXMgYSByZWNvcmRpbmcuIFRlc3RpbmcgMSAyIDMuCgkBRQkAQNitypqw
1vKCVtCOmX0oaetEo3MK1nXRXnjrKCGxF4M7rM0sPqniTe+tFQRbek9bpxn+CrrJxWG68+CU8B9S
AgUBAekZrwEJAFMJABABiyLrgKYUY94vQZ6Y/sIWGQEGaW50ZXI5OQIBAwkDIDXe2CLiqEKZ5lCn
vxbW54NnoAbMLa8Myu1V4/wUDH4wqQQEGArQH6kFBAwKzh8VBgkBVgkAQJvJDdXyyu0/bvrvPWc+
aq5nJBikzet/mrHovDGwoLwvZQU2nui/fENyB4bs7a6/k6R/a3paUPSuTCr6tzYQlwsJARABiyLm
jKJQruGSyyP2TPZ9
`

const TEST_ROOT9_CERT = `
--------------------------[ root9 - Cert chain ]----------------------------
2Q6yAekZrgEJAFIJABABiyLmjKJQruGSyyP2TPZ9GQEFcm9vdDk5AgEDCQMg0QHo4s60w7996y0E
dzsRUZifqkE/ajltmTXs7xjFmUGpBAQYCtAfqQUEDArOHxUGCQFWCQBAC1QKV0pxhpPiwLACGqRh
9jQNlCfTs0f94+OkoEcQJ618M8cnIXpgDki15v3oHvcKY2wGqDb4MbSHSJf89x/CDAkBEAGLIuaM
olCu4ZLLI/ZM9n0=
`

func TestVerifyPayload(t *testing.T) {
	var err error
	var block, rblock []byte
	var chain, rchain []DasCertPayload
	var ppkey int

	// --- Add root to trusted certs ---
	rblock, _, err = TextToBinaryBlock(TEST_ROOT9_CERT)
	require.Nil(t, err)
	ppkey, rchain, err = LoadPubBlock(rblock)
	require.Nil(t, err)
	require.Equal(t, PUB_CERTCHAIN, ppkey)
	root := rchain[0].cert
	trustedCerts[hex.EncodeToString(root.CertID)] = root

	// ---
	block, _, err = TextToBinaryBlock(TEST_PAYLOAD9)
	require.Nil(t, err)
	ppkey, chain, err = LoadPubBlock(block)
	require.Nil(t, err)
	require.Equal(t, PUB_PAYLOAD, ppkey)

	err = Verify(chain)
	require.Nil(t, err)

	require.Equal(t, "This is a recording. Testing 1 2 3.\n", string(chain[0].payload))
	// we know its a string in this case.
}

// Here we are hoping for the "next issuer cert is missing" error to happen at some point along the way.
// (Which it wont unless we hack the outer envelope datalen.)
func T_estTruncatedPayload(t *testing.T) {
	var err error
	var block, pristineBlock, rblock []byte
	var chain, rchain []DasCertPayload
	var ppkey, cn, n, i int

	// --- Add root to trusted certs ---
	rblock, _, err = TextToBinaryBlock(TEST_ROOT9_CERT)
	require.Nil(t, err)
	ppkey, rchain, err = LoadPubBlock(rblock)
	require.Nil(t, err)
	require.Equal(t, PUB_CERTCHAIN, ppkey)
	root := rchain[0].cert
	trustedCerts[hex.EncodeToString(root.CertID)] = root

	pristineBlock, _, err = TextToBinaryBlock(TEST_PAYLOAD9)
	require.Nil(t, err)
	block = make([]byte, len(pristineBlock))

	for n = len(pristineBlock); n >= 0; n-- {
		cn = copy(block, pristineBlock)
		require.Equal(t, len(pristineBlock), cn)
		// Zero-out bytes from n to end of buffer
		for i = n; i < len(block); i++ {
			block[i] = 0
		}

		fmt.Printf("Load %3d : ", n)
		_, chain, err = LoadPubBlock(block)
		if err == nil {
			fmt.Printf("Ok,   Verify : ")
			err = Verify(chain)
			fmt.Println(err)
		} else {
			fmt.Println(err)
		}

	}

}

// ---------------------------------------------------------------------------------------------------------------------
func T_estGlitchFuzz(t *testing.T) { // disabled sometimes
	var err error
	var block []byte
	var lines []string

	var chain, correctChain []DasCertPayload
	var ppkey int
	var badErrors int

	block, lines, err = TextToBinaryBlock(TEST_ROOT6_PUB)
	// block, lines, err = TextToBinaryBlock(TEST_PAYLOAD9)
	require.Nil(t, err, "TextToBinaryBlock")

	// Take the whole buf, clock each byte from 0 to 255. Skip the legit byte.
	buf := make([]byte, len(block))

	for loc := 0; loc < len(block); loc++ {

		for ibyt := 0; ibyt < 256; ibyt++ {
			copy(buf, block) // slow but safe
			byt := byte(ibyt)
			// fmt.Printf("at %2d val %08b (ok %08b)  \n", loc, byt, block[loc])
			if byt == block[loc] { // legit value
				continue
			}

			buf[loc] = byt // glitch byte

			ppkey, chain, err = LoadPubBlock(buf)
			if err != nil {
				// fmt.Printf(" Load   error: %v\n", err)
				continue
			}
			if ppkey != PUB_CERTCHAIN {
				// fmt.Printf(" ppkey not PUB_CERTCHAIN\n")
				continue
			}
			_ = lines
			err = Verify(chain)
			if err != nil {
				fmt.Printf("at %2d val %08b (ok %08b)  ", loc, byt, block[loc])
				fmt.Printf(" Verify error: %v\n", err)
			} else {
				fmt.Printf("at %2d val %08b  (c val %08b) ", loc, byt, block[loc])
				fmt.Printf(" ** No error but there should be ** ")
				badErrors++
				if reflect.DeepEqual(correctChain, chain) {
					fmt.Printf(" - but chains are equal")
				} else {
					fmt.Printf(" ! and chains are DIFFERENT !")
					fmt.Println()
				}
				// spew.Dump(chain)
				fmt.Println()
				// panic("No error when there should be an error!")
			}
		}
		// fmt.Println("end of byt loop")
	}
	_ = correctChain
	_ = buf
	fmt.Println("Done. ")
	fmt.Println("Errors where there shouldn't be errors: ", badErrors)
}

func DumpChain(chain []DasCertPayload) {
	fmt.Println("chain : ")
	for i, z := range chain {
		fmt.Println("--- ", i, " ---")
		spew.Dump(z)
	}
}
