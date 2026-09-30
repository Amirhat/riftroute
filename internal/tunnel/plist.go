package tunnel

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// parsePlist reads an XML property list (what a .mobileconfig is) into Go
// values: map[string]any for <dict>, []any for <array>, string, int64,
// float64, bool, []byte for <data>, time.Time for <date>. Binary plists
// aren't read: a configuration profile is XML (or XML signed, see
// unwrapSigned).
func parsePlist(data []byte) (any, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	// Profiles declare Apple's DTD; nothing is fetched or expanded.
	d.Entity = xml.HTMLEntity
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("not a property list: %w", err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local != "plist" {
				return nil, fmt.Errorf("not a property list (it starts with <%s>)", se.Name.Local)
			}
			v, err := plistNext(d, 0)
			if err != nil {
				return nil, err
			}
			return v, nil
		}
	}
}

// plistMaxDepth bounds nesting: a profile is a few levels deep.
const plistMaxDepth = 32

// plistNext reads the next value element.
func plistNext(d *xml.Decoder, depth int) (any, error) {
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("property list: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return plistValue(d, t, depth)
		case xml.EndElement:
			return nil, errPlistEnd
		}
	}
}

var errPlistEnd = errors.New("end of container")

func plistValue(d *xml.Decoder, se xml.StartElement, depth int) (any, error) {
	if depth > plistMaxDepth {
		return nil, errors.New("property list nested too deeply")
	}
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, fmt.Errorf("property list: %w", err)
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return m, nil
			case xml.StartElement:
				if t.Name.Local != "key" {
					return nil, fmt.Errorf("property list: <%s> where a <key> belongs", t.Name.Local)
				}
				k, err := plistText(d)
				if err != nil {
					return nil, err
				}
				v, err := plistNext(d, depth+1)
				if err != nil {
					if errors.Is(err, errPlistEnd) {
						return nil, fmt.Errorf("property list: key %q has no value", k)
					}
					return nil, err
				}
				m[k] = v
			}
		}
	case "array":
		var a []any
		for {
			v, err := plistNext(d, depth+1)
			if errors.Is(err, errPlistEnd) {
				return a, nil
			}
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
	case "string":
		return plistText(d)
	case "integer":
		s, err := plistText(d)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("property list: bad <integer> %q", s)
		}
		return n, nil
	case "real":
		s, err := plistText(d)
		if err != nil {
			return nil, err
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil, fmt.Errorf("property list: bad <real> %q", s)
		}
		return f, nil
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	case "data":
		s, err := plistText(d)
		if err != nil {
			return nil, err
		}
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil, errors.New("property list: bad <data>")
		}
		return b, nil
	case "date":
		s, err := plistText(d)
		if err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("property list: bad <date> %q", s)
		}
		return t, nil
	}
	return nil, fmt.Errorf("property list: unknown element <%s>", se.Name.Local)
}

// plistText reads an element's text up to its end tag.
func plistText(d *xml.Decoder) (string, error) {
	var b strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return "", fmt.Errorf("property list: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			b.Write(t)
		case xml.EndElement:
			return b.String(), nil
		case xml.StartElement:
			return "", fmt.Errorf("property list: <%s> inside a text value", t.Name.Local)
		}
	}
}

// unwrapSigned returns the profile a signed .mobileconfig carries: a CMS
// SignedData (DER) whose content is the XML. The signature isn't checked —
// it vouches for who made the profile, which the user already decided by
// importing it; what the profile says is checked like any other.
func unwrapSigned(data []byte) ([]byte, bool) {
	if xml, ok := unwrapDER(data); ok {
		return xml, true
	}
	// A BER encoding (indefinite lengths, which encoding/asn1 doesn't read)
	// still carries the XML as one piece, unless its signer chunked it.
	if len(data) > 0 && data[0] == 0x30 {
		if i := bytes.Index(data, []byte("<?xml")); i >= 0 {
			if j := bytes.Index(data[i:], []byte("</plist>")); j >= 0 {
				return data[i : i+j+len("</plist>")], true
			}
		}
	}
	return nil, false
}

// unwrapDER is unwrapSigned for a DER SignedData.
func unwrapDER(data []byte) ([]byte, bool) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if rest, err := asn1.Unmarshal(data, &ci); err != nil || len(rest) != 0 ||
		!ci.ContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return nil, false
	}
	// SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
	// [0] certificates, [1] crls, signerInfos }: the third element.
	var sd asn1.RawValue
	if _, err := asn1.Unmarshal(ci.Content.FullBytes, &sd); err != nil || !sd.IsCompound {
		return nil, false
	}
	elems := sd.Bytes
	var encap asn1.RawValue
	for i := 0; i < 3; i++ {
		var err error
		if elems, err = asn1.Unmarshal(elems, &encap); err != nil {
			return nil, false
		}
	}
	// EncapsulatedContentInfo ::= SEQUENCE { eContentType, [0] EXPLICIT OCTET STRING }
	var ec struct {
		ContentType asn1.ObjectIdentifier
		Content     []byte `asn1:"explicit,tag:0,optional"`
	}
	if _, err := asn1.Unmarshal(encap.FullBytes, &ec); err != nil || len(ec.Content) == 0 {
		return nil, false
	}
	return ec.Content, true
}
