package ldap

import (
	ber "github.com/go-asn1-ber/asn1-ber"
)

type UnbindRequest struct{}

func (bind *UnbindRequest) ToBER() *ber.Packet {
	return ber.Encode(ber.ClassApplication, ber.TypePrimitive, ApplicationUnbindRequest, nil, "Unbind Request")
}

func DecodeUnbindRequest(p *ber.Packet) (*UnbindRequest, error) {
	return &UnbindRequest{}, nil
}
