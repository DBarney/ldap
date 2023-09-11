package ldap

import (
	ber "github.com/go-asn1-ber/asn1-ber"
)

type SearchRequest struct {
	BaseDN       string
	Scope        int
	DerefAliases int
	SizeLimit    int
	TimeLimit    int
	TypesOnly    bool
	Filter       string
	Attributes   []string
	Controls     []Control
}

func (search *SearchRequest) ToBER() *ber.Packet {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchRequest, nil, "Search Request")
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, search.BaseDN, "Base DN"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(search.Scope), "Scope"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(search.DerefAliases), "Deref Aliases"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(search.SizeLimit), "Size Limit"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(search.TimeLimit), "Time Limit"))
	request.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, search.TypesOnly, "Types Only"))
	// compile and encode filter
	filterPacket, _ := CompileFilter(search.Filter)
	request.AppendChild(filterPacket)
	// encode attributes
	attributesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attribute := range search.Attributes {
		attributesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attribute, "Attribute"))
	}
	request.AppendChild(attributesPacket)
	return request
}

func DecodeSearchRequest(p *ber.Packet) (*SearchRequest, error) {

	if len(p.Children) != 8 {
		return nil, ErrBadProtocol
	}

	// Parse the request
	baseObject, ok := p.Children[0].Value.(string)
	if !ok {
		return nil, ErrBadProtocol
	}
	s, ok := p.Children[1].Value.(int64)
	if !ok {
		return nil, ErrBadProtocol
	}
	scope := int(s)
	d, ok := p.Children[2].Value.(int64)
	if !ok {
		return nil, ErrBadProtocol
	}
	derefAliases := int(d)
	s, ok = p.Children[3].Value.(int64)
	if !ok {
		return nil, ErrBadProtocol
	}
	sizeLimit := int(s)
	t, ok := p.Children[4].Value.(int64)
	if !ok {
		return nil, ErrBadProtocol
	}
	timeLimit := int(t)
	typesOnly := false
	if p.Children[5].Value != nil {
		typesOnly, ok = p.Children[5].Value.(bool)
		if !ok {
			return nil, ErrBadProtocol
		}
	}
	filter, err := DecompileFilter(p.Children[6])
	if err != nil {
		return nil, err
	}
	attributes := []string{}
	for _, attr := range p.Children[7].Children {
		a, ok := attr.Value.(string)
		if !ok {
			return nil, ErrBadProtocol
		}
		attributes = append(attributes, a)
	}
	return &SearchRequest{
		BaseDN:       baseObject,
		Scope:        scope,
		DerefAliases: derefAliases,
		SizeLimit:    sizeLimit,
		TimeLimit:    timeLimit,
		TypesOnly:    typesOnly,
		Filter:       filter,
		Attributes:   attributes,
	}, nil
}
