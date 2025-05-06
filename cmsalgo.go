package pkcs7

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

var oidCMSAlgorithmProtection = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52}

type cmsAlgorithmProtection struct {
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignatureAlgorithm pkix.AlgorithmIdentifier
}

func newCMSAlgorithmProtectionAttr(digestAlg, sigAlg pkix.AlgorithmIdentifier) (Attribute, error) {
	cmsProt := cmsAlgorithmProtection{
		DigestAlgorithm:    digestAlg,
		SignatureAlgorithm: sigAlg,
	}
	val, err := asn1.Marshal(cmsProt)
	if err != nil {
		return Attribute{}, fmt.Errorf("failed to marshal CMS algorithm protection attributes: %v", err)
	}
	attr := Attribute{
		Type: oidCMSAlgorithmProtection,
		Value: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      encodeAsSet(val),
		},
	}
	return attr, nil
}

func encodeAsSet(data []byte) []byte {
	rawSet, _ := asn1.Marshal([]asn1.RawValue{
		{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      data,
		},
	})
	return rawSet
}
