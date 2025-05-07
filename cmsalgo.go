package pkcs7

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

var oidCMSAlgorithmProtection = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52}

type cmsAlgorithmProtection struct {
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignatureAlgorithm pkix.AlgorithmIdentifier `asn1:"tag:1,explicit,optional"`
}

func newCMSAlgorithmProtectionAttr(digestAlg, sigAlg pkix.AlgorithmIdentifier) (Attribute, error) {
	cmsProt := cmsAlgorithmProtection{
		DigestAlgorithm:    digestAlg,
		SignatureAlgorithm: sigAlg,
	}
	value, err := asn1.Marshal(cmsProt)
	if err != nil {
		return Attribute{}, fmt.Errorf("failed to marshal CMS algorithm protection attributes: %v", err)
	}
	return Attribute{
		Type:  oidCMSAlgorithmProtection,
		Value: asn1.RawValue{Class: 0, Tag: asn1.TagSequence, IsCompound: true, Bytes: value},
	}, nil
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
