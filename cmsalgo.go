package pkcs7

import (
	"encoding/asn1"
)

func newCMSAlgorithmProtectionAttr() (Attribute, error) {
	digestAlgBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      0,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      mustMarshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}), // sha256 OID
	})
	if err != nil {
		return Attribute{}, err
	}

	sigAlgOID, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11})
	sigAlgNULL, _ := asn1.Marshal(asn1.RawValue{Tag: 5, Class: 0, IsCompound: false, Bytes: []byte{}})

	sigAlgBytes := append(sigAlgOID, sigAlgNULL...)

	sigAlgTagged, err := asn1.Marshal(asn1.RawValue{
		Class:      2,
		Tag:        1,
		IsCompound: true,
		Bytes:      sigAlgBytes,
	})
	if err != nil {
		return Attribute{}, err
	}

	final := append(digestAlgBytes, sigAlgTagged...)

	return Attribute{
		Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52},
		Value: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      final,
		},
	}, nil
}

func mustMarshal(val interface{}) []byte {
	b, err := asn1.Marshal(val)
	if err != nil {
		panic(err)
	}
	return b
}
