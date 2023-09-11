package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

type ExtendedRequest struct {
	requestName  string
	requestValue string
}

func (ext *ExtendedRequest) ToBER() *ber.Packet {

	return nil
}

func DecodeExtendedRequest(p *ber.Packet) (*ExtendedRequest, error) {
	if len(p.Children) != 1 && len(p.Children) != 2 {
		return nil, ErrBadProtocol
	}
	name := ber.DecodeString(p.Children[0].Data.Bytes())
	var val string
	if len(p.Children) == 2 {
		val = ber.DecodeString(p.Children[1].Data.Bytes())
	}
	return &ExtendedRequest{
		requestName:  name,
		requestValue: val,
	}, nil
}
