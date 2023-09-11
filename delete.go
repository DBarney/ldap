package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

type DeleteRequest struct {
	dn string
}

func (del *DeleteRequest) ToBER() *ber.Packet {

	return nil
}

func DecodeDeleteRequest(p *ber.Packet) (*DeleteRequest, error) {
	return &DeleteRequest{
		dn: ber.DecodeString(p.Data.Bytes()),
	}, nil
}
