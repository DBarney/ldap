package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

type AddRequest struct {
	dn         string
	attributes []Attribute
}

func (add *AddRequest) ToBER() *ber.Packet {

	return nil
}

func DecodeAddRequest(p *ber.Packet) (*AddRequest, error) {
	var ok bool
	if len(p.Children) != 2 {
		return nil, ErrBadProtocol
	}
	addReq := &AddRequest{}
	addReq.dn, ok = p.Children[0].Value.(string)
	if !ok {
		return nil, ErrBadProtocol
	}
	addReq.attributes = []Attribute{}
	for _, attr := range p.Children[1].Children {
		if len(attr.Children) != 2 {
			return nil, ErrBadProtocol
		}

		a := Attribute{}
		a.attrType, ok = attr.Children[0].Value.(string)
		if !ok {
			return nil, ErrBadProtocol
		}
		a.attrVals = []string{}
		for _, val := range attr.Children[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				return nil, ErrBadProtocol
			}
			a.attrVals = append(a.attrVals, v)
		}
		addReq.attributes = append(addReq.attributes, a)
	}
	return addReq, nil
}
