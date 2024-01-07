package c3

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/oddy/b3-go"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/sign"
)

// Policy: we are not supporting verifying of vis fields (vis maps) at this time.
// Todo: switch the error handling to fmt.Errorf instead of errors.Wrap so that errors.Is works properly.

const (
	// --- Top-level tag values ---
	PUB_CSR         = 10
	DUALBLOCK       = 11
	PUB_PAYLOAD     = 12 // cert chain with a payload as the first entry
	BARE_PAYLOAD    = 13 // literally just payload bytes but tagged with a header tag.
	PUB_CERTCHAIN   = 14 // cert chain with a cert as the first entry
	PRIV_CRCWRAPPED = 15 // "priv data with a crc32 integrity check"
	// --- Public-part chain-level ---
	HDR_DAS = 0x19 // "data_part and sig_part structure"
)

type Cert struct {
	CertID      []byte    `b3.type:"BYTES"     b3.tag:"0"  b3.req:"y"`
	SubjectName string    `b3.type:"UTF8"      b3.tag:"1"  b3.req:"y"`
	KeyType     int       `b3.type:"UVARINT"   b3.tag:"2"  b3.req:"y"`
	PublicKey   []byte    `b3.type:"BYTES"     b3.tag:"3"  b3.req:"y"`
	ExpiryDate  time.Time `b3.type:"BASICDATE" b3.tag:"4"  b3.req:"y"` //    (this is for b3.BASICDATE so it's ONLY date-values)
	IssuedDate  time.Time `b3.type:"BASICDATE" b3.tag:"5"  b3.req:"y"`
	CertType    string    `b3.type:"UTF8"      b3.tag:"6"  b3.req:"n"` //    // optional (zero value ok here)
}

type Signature struct {
	Signature     []byte `b3.type:"BYTES"     b3.tag:"0"   b3.req:"y"`
	SigningCertID []byte `b3.type:"BYTES"     b3.tag:"1"   b3.req:"n"` // optional
}

// This is a DAS (data-and-sig) with the data & sig bytes (made for us by B3)
type DasBytes struct {
	DataPart []byte `b3.type:"BYTES"     b3.tag:"0"  b3.req:"y"`
	SigPart  []byte `b3.type:"BYTES"     b3.tag:"1"  b3.req:"y"`
}

// This is a DAS with everything unpacked (certs & payloads etc) made by Load for Verify to use
type DasCertPayload struct {
	DataPart []byte
	SigPart  []byte
	Payload  []byte
	Cert     Cert
	Sig      Signature
}

// Global variables

func check(e error) {
	if e != nil {
		fmt.Printf("---stack trace---\n %+v \n------------------\n", e)
		panic(e)
	}
}

func SplitLines(input string) []string {
	normalized := strings.Replace(input, "\r\n", "\n", -1) // Normalize Windows line endings
	return strings.Split(normalized, "\n")
}

// fixme: These need to change because errors.New isn't supposed to be used like this. (The stacktrace will start here instead of where the error is created.)
//        See if we can come up with something else that works with the one time we use errors.Is

var (
	TextStructureError = errors.New("File text vertical structure is invalid")
	StructureError     = errors.New("Binary structure is invalid")
	NoLinkError        = errors.New("Chain does not link to trusted certs")
	VerifyError        = errors.New("Signature failed to verify")
)

var trustedCerts map[string]Cert

func init() {
	trustedCerts = make(map[string]Cert) // Actually allocate the trust store map
}

func TextToBinaryBlock(textPart string) ([]byte, []string, error) {
	// --- Ensure vertical structure is legit ---
	// 1 or no header line (-), immediately followed by 0 or more VF lines ([),
	// immediately followed by base64 then: a mandatory whitespace (e.g empty line)
	// (or a line starting with a -)
	lines := SplitLines(textPart)
	// Make string of first-chars from each line
	var c0s string
	for _, line := range lines {
		if len(line) == 0 {
			c0s += " "
		} else {
			c0s += string(line[0])
		}
	}
	c0s += " "
	// Check against structural regex
	re := regexp.MustCompile(`^\s*(-?)(\[*)([a-zA-Z0-9/=+]+)[ \-]`)
	matches := re.FindStringSubmatchIndex(c0s)
	if matches == nil {
		return nil, nil, TextStructureError
	}
	vfLines := lines[matches[4]:matches[5]]
	b64Lines := lines[matches[6]:matches[7]]
	b64Block := strings.Join(b64Lines, "")
	bytesPart, err := base64.StdEncoding.DecodeString(b64Block)
	if err != nil {
		return nil, nil, err
	}
	return bytesPart, vfLines, nil
}

func InIntList(itm int, intList []int) bool {
	for _, a := range intList {
		if a == itm {
			return true
		}
	}
	return false
}

func ExpectKeyHeader(wantKeys []int, wantType int, buf []byte) (int, int, error) { // key,index,err
	if len(buf) == 0 {
		return 0, 0, errors.Wrap(StructureError, "No data - buffer is empty")
	}
	h, index, err := b3.DecodeHeader(buf)
	if err != nil {
		return 0, index, errors.Wrap(StructureError, "Header structure is invalid")
	}
	key, ok := h.Key.(int)
	if !ok {
		return 0, index, errors.Wrap(StructureError, "Incorrect type of key in header (should be int)")
	}
	if !InIntList(key, wantKeys) {
		return 0, index, errors.Wrap(StructureError, "Incorrect key in header")
	}
	if wantType != 0 && wantType != h.DataType {
		return 0, index, errors.Wrap(StructureError, "Incorrect type in header")
	}
	if !h.HasData {
		return 0, index, errors.Wrap(StructureError, "Invalid header, no hasData")
	}
	if index == len(buf) {
		return 0, index, errors.Wrap(StructureError, "No data after header - buffer is empty")
	}
	if h.DataLen != (len(buf) - index) {
		return 0, index, errors.Wrap(StructureError, "Outer header datalen doesn't match buffer len")
	}
	return key, index, nil
}

// initial header, PUB_CSR, PUB_PAYLOAD or PUB_CERTCHAIN
// we dont verify CSRs so bail if it's that.

func LoadPubBlock(publicPart []byte) (ppkey int, chain []DasCertPayload, err error) { // ppkey, chain
	var index int
	wantKeys := []int{PUB_PAYLOAD, PUB_CERTCHAIN}
	ppkey, index, err = ExpectKeyHeader(wantKeys, b3.LIST, publicPart)
	if err != nil {
		err = errors.Wrap(err, "load pub header")
		return
	}

	// we're supposed to check the list items's keys are correct too.
	// their keys should be HDR_DAS

	dasChain, err := b3.BufToListOfStructs(publicPart[index:], DasBytes{}, HDR_DAS)
	if err != nil {
		err = errors.Wrap(err, "load pub das chain")
		return
	}

	// Now we gotta concretize and unpack dasChain to a chain of DasCertPayloads
	for i, idas := range dasChain {
		das, ok := idas.(DasBytes)
		if !ok {
			err = errors.Wrap(StructureError, "fail concretizing das item")
			return
		}
		dcp := DasCertPayload{DataPart: das.DataPart, SigPart: das.SigPart}
		if i == 0 && ppkey == PUB_PAYLOAD {
			dcp.Payload = dcp.DataPart
		} else {
			cert := Cert{}
			err = b3.BufToStruct(dcp.DataPart, &cert)
			if err != nil {
				err = errors.Wrap(err, "fail unpacking cert")
				return
			}
			dcp.Cert = cert
		}
		sig := Signature{}
		err = b3.BufToStruct(dcp.SigPart, &sig)
		if err != nil {
			err = errors.Wrap(err, "fail unpacking Signature")
			return
		}
		dcp.Sig = sig

		chain = append(chain, dcp)
	}
	// now we return ppkey, chain, error
	return
}

func AddTrusted(block []byte) error {
	var chain []DasCertPayload
	var ppkey int
	var err error

	ppkey, chain, err = LoadPubBlock(block)
	if err != nil {
		return errors.Wrap(err, "AddTrusted loading block")
	}
	if ppkey != PUB_CERTCHAIN {
		return errors.New("block does not contain a CERTCHAIN")
	}
	err = Verify(chain)
	// -- chain does not link to trusted certs error is expected here. --
	// -- Anything else is still bad though.                           --
	if err != nil && !errors.Is(err, NoLinkError) { // todo: we need to switch this to a string compare and not use errors.Is because we are using errors.New wrong.
		return err
	}
	// -- Put the cert in the trust store --
	root := chain[0].Cert
	trustedCerts[hex.EncodeToString(root.CertID)] = root
	return nil
}

func Verify(chain []DasCertPayload) error {
	certsById := make(map[string]Cert) // not string-ified certID
	var nextCert Cert

	if len(chain) == 0 {
		return errors.Wrap(StructureError, "Cannot verify - no cert chain present")
	}
	for _, dcp := range chain {
		scertid := hex.EncodeToString(dcp.Cert.CertID)
		if scertid != "" {
			certsById[scertid] = dcp.Cert
		}
	}
	foundInTrusted := false

	for i, dcp := range chain {
		// --- Find the 'next cert' ie the one which verifies our signature ---
		signingCertId := hex.EncodeToString(dcp.Sig.SigningCertID) // need hashable value, which []byte isn't.
		if len(signingCertId) == 0 {
			// --- no signing-id means "next cert in the chain" ---
			if i+1 >= len(chain) { // have we fallen off the end?
				return errors.Wrap(VerifyError, ctmn(dcp)+"Next issuer cert is missing")
			}
			nextCert = chain[i+1].Cert
		} else {
			// --- got a name, look in trusted & in our own chain for it ---
			trCert, trFound := trustedCerts[signingCertId]
			usCert, usFound := certsById[signingCertId]
			// --- got a name, look in trusted for it ---
			if trFound {
				nextCert = trCert
				foundInTrusted = true
				// --- otherwise look in our own supplied chain ---
			} else if usFound {
				nextCert = usCert
			} else {
				msg := fmt.Sprintf("%s signing cert not found (id %s)", ctmn(dcp), signingCertId)
				return errors.Wrap(VerifyError, msg)
			}
		}

		// --- Actually verify the signature ---
		err := KeypairsVerify(nextCert, dcp.DataPart, dcp.Sig.Signature)
		if err != nil {
			return errors.Wrap(err, "Signature failed to verify")
		}
		// --- Now do the next dcp in line ---
	} // end for

	if foundInTrusted {
		return nil
	}
	return errors.Wrap(NoLinkError, "Chain does not link to trusted certs")
}

func KeypairsVerify(cert Cert, dataBytes []byte, sigBytes []byte) error {
	// make nacl verify key from cert.publicKey
	// vk,verify(data bytes, sig bytes)
	var naclVerifyKeyAry [32]byte
	copy(naclVerifyKeyAry[:], cert.PublicKey)
	signedDataBytes := bytes.Join([][]byte{sigBytes, dataBytes}, nil)
	x, valid := sign.Open(nil, signedDataBytes, &naclVerifyKeyAry) // Note: make sure we can pass nil to sign.Open
	if !valid {
		return errors.Wrap(VerifyError, "nacl sign.Open failed")
	}
	_ = x // x is the payload i think.
	return nil
}

func ctmn(dcp DasCertPayload) string {
	if len(dcp.Cert.CertID) > 0 {
		return fmt.Sprintf(" (cert %s) ", dcp.Cert.SubjectName)
	}
	return " (payload) "
}

// ---- Metadata ---

// Note: these is not inherently secure, use Verify for that. These just retrieve names and assume relationships
//       based off of the CertID
// Note: this only goes as far as the first cert in the trust store, not necessarily all the way to the root.
//       (we'd need a "who signed what" registry for the trust store for that, and i cbf rn.

func Blankify(in string) string {
	if len(in) > 0 {
		return in
	} else {
		return "<none>"
	}
}

// GPT told me that the way to generalise having to access different struct members with all other code
// being the same, is to pretty much use function pointer/callback.

func ChainMetadata(chain []DasCertPayload, FieldEx func(*Cert) string) []string {
	var results []string

	if len(chain) == 0 {
		return []string{}
	}

	for _, dcp := range chain {
		results = append(results, Blankify(FieldEx(&dcp.Cert))) // subjectName or certType
	}

	lastDcp := chain[len(chain)-1]
	lastSigningCertIdHex := hex.EncodeToString(lastDcp.Sig.SigningCertID)

	// --- lastSigningCertId should be in trusted. ---
	trCert, trFound := trustedCerts[lastSigningCertIdHex]
	if !trFound {
		results = append(results, "!NotFound!")
		return results
	}

	results = append(results, Blankify(FieldEx(&trCert))) // subjectName or certType
	return results
}

func VNames(chain []DasCertPayload) []string {
	fieldGetSubjectName := func(c *Cert) string {
		return c.SubjectName
	}
	return ChainMetadata(chain, fieldGetSubjectName)
}

func VTypes(chain []DasCertPayload) []string {
	fieldGetCertType := func(c *Cert) string {
		return c.CertType
	}
	return ChainMetadata(chain, fieldGetCertType)
}
