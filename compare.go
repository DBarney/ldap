package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

type CompareRequest struct {
	dn  string
	ava []AttributeValueAssertion
}

func (cmp *CompareRequest) ToBER() *ber.Packet {

	return nil
}

func DecodeCompareRequest(p *ber.Packet) (*CompareRequest, error) {
	if len(p.Children) != 2 {
		return nil, ErrBadProtocol
	}
	var ok bool
	compReq := CompareRequest{}
	compReq.dn, ok = p.Children[0].Value.(string)
	if !ok {
		return nil, ErrBadProtocol
	}
	ava := p.Children[1]
	if len(ava.Children) != 2 {
		return nil, ErrBadProtocol
	}
	attr, ok := ava.Children[0].Value.(string)
	if !ok {
		return nil, ErrBadProtocol
	}
	val, ok := ava.Children[1].Value.(string)
	if !ok {
		return nil, ErrBadProtocol
	}
	compReq.ava = []AttributeValueAssertion{AttributeValueAssertion{attr, val}}
	return &compReq, nil
}
