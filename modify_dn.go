package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

type ModifyDNRequest struct {
	dn           string
	newrdn       string
	deleteoldrdn bool
	newSuperior  string
}

func (mod *ModifyDNRequest) ToBER() *ber.Packet {

	return nil
}

func DecodeModifyDNRequest(p *ber.Packet) (*ModifyDNRequest, error) {
	if len(p.Children) != 3 && len(p.Children) != 4 {
		return nil, ErrBadProtocol
	}
	var ok bool
	mdnReq := ModifyDNRequest{}
	mdnReq.dn, ok = p.Children[0].Value.(string)
	if !ok {
		return nil, ErrBadProtocol
	}
	mdnReq.newrdn, ok = p.Children[1].Value.(string)
	if !ok {
		return nil, ErrBadProtocol
	}
	mdnReq.deleteoldrdn, ok = p.Children[2].Value.(bool)
	if !ok {
		return nil, ErrBadProtocol
	}
	if len(p.Children) == 4 {
		mdnReq.newSuperior, ok = p.Children[3].Value.(string)
		if !ok {
			return nil, ErrBadProtocol
		}
	}
	return &mdnReq, nil
}
