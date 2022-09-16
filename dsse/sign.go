package dsse

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"

	"github.com/testifysec/go-witness/cryptoutil"
)

type Timestamper interface {
	Timestamp(context.Context, []byte) ([]byte, error)
}

type signOptions struct {
	signers      []cryptoutil.Signer
	timestampers []Timestamper
}

type SignOption func(*signOptions)

func SignWithSigners(signers ...cryptoutil.Signer) SignOption {
	return func(so *signOptions) {
		so.signers = signers
	}
}

func SignWithTimestampers(timestampers ...Timestamper) SignOption {
	return func(so *signOptions) {
		so.timestampers = timestampers
	}
}

func Sign(bodyType string, body io.Reader, opts ...SignOption) (Envelope, error) {
	so := &signOptions{}
	for _, opt := range opts {
		opt(so)
	}

	env := Envelope{}
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return env, err
	}

	env.PayloadType = bodyType
	env.Payload = bodyBytes
	env.Signatures = make([]Signature, 0)
	pae := preauthEncode(bodyType, bodyBytes)
	for _, signer := range so.signers {
		sig, err := signer.Sign(bytes.NewReader(pae))
		if err != nil {
			return env, err
		}

		keyID, err := signer.KeyID()
		if err != nil {
			return env, err
		}

		dsseSig := Signature{
			KeyID:     keyID,
			Signature: sig,
		}

		for _, timestamper := range so.timestampers {
			timestamp, err := timestamper.Timestamp(context.TODO(), sig)
			if err != nil {
				return env, err
			}

			dsseSig.Timestamps = append(dsseSig.Timestamps, SignatureTimestamp{
				Type: TimestampRFC3161,
				Data: timestamp,
			})
		}

		if trustBundler, ok := signer.(cryptoutil.TrustBundler); ok {
			leaf := trustBundler.Certificate()
			intermediates := trustBundler.Intermediates()
			if leaf != nil {
				dsseSig.Certificate = pem.EncodeToMemory(&pem.Block{Type: PemTypeCertificate, Bytes: leaf.Raw})
			}

			for _, intermediate := range intermediates {
				dsseSig.Intermediates = append(dsseSig.Intermediates, pem.EncodeToMemory(&pem.Block{Type: PemTypeCertificate, Bytes: intermediate.Raw}))
			}
		}

		env.Signatures = append(env.Signatures, dsseSig)
	}

	return env, nil
}
