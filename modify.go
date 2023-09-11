package ldap

import (
	"log"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	AddAttribute     = 0
	DeleteAttribute  = 1
	ReplaceAttribute = 2
)

var LDAPModifyAttributeMap = map[uint64]string{
	AddAttribute:     "Add",
	DeleteAttribute:  "Delete",
	ReplaceAttribute: "Replace",
}

type ModifyRequest struct {
	Dn                string
	AddAttributes     []PartialAttribute
	DeleteAttributes  []PartialAttribute
	ReplaceAttributes []PartialAttribute
}

type PartialAttribute struct {
	AttrType string
	AttrVals []string
	op       int64
}

func (mod *ModifyRequest) ToBER() *ber.Packet {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyRequest, nil, "Modify Request")
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, mod.Dn, "DN"))

	ops := map[uint][]PartialAttribute{
		AddAttribute:     mod.AddAttributes,
		DeleteAttribute:  mod.DeleteAttributes,
		ReplaceAttribute: mod.ReplaceAttributes,
	}
	changes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Changes")
	for op, attributes := range ops {
		for _, attribute := range attributes {
			change := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Change")
			change.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, op, "Operation"))
			change.AppendChild(attribute.encode())
			changes.AppendChild(change)
		}
	}
	request.AppendChild(changes)
	return request
}

func (p *PartialAttribute) encode() *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, p.AttrType, "Type"))
	set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "AttributeValue")
	for _, value := range p.AttrVals {
		set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Vals"))
	}
	seq.AppendChild(set)
	return seq
}

func (m *ModifyRequest) Add(attrType string, attrVals []string) {
	m.AddAttributes = append(m.AddAttributes, PartialAttribute{AttrType: attrType, AttrVals: attrVals})
}

func (m *ModifyRequest) Delete(attrType string, attrVals []string) {
	m.DeleteAttributes = append(m.DeleteAttributes, PartialAttribute{AttrType: attrType, AttrVals: attrVals})
}

func (m *ModifyRequest) Replace(attrType string, attrVals []string) {
	m.ReplaceAttributes = append(m.ReplaceAttributes, PartialAttribute{AttrType: attrType, AttrVals: attrVals})
}

func DecodeModifyRequest(p *ber.Packet) (*ModifyRequest, error) {
	if len(p.Children) != 2 {
		return nil, ErrBadProtocol
	}
	var ok bool
	modReq := &ModifyRequest{}
	modReq.Dn, ok = p.Children[0].Value.(string)
	if !ok {
		return nil, ErrBadProtocol
	}
	for _, change := range p.Children[1].Children {
		attr, err := DecodePartialAttribute(change)
		if err != nil {
			return nil, err
		}
		switch attr.op {
		default:
			log.Printf("Unrecognized Modify attribute %d", attr.op)
			return nil, ErrBadProtocol
		case AddAttribute:
			modReq.Add(attr.AttrType, attr.AttrVals)
		case DeleteAttribute:
			modReq.Delete(attr.AttrType, attr.AttrVals)
		case ReplaceAttribute:
			modReq.Replace(attr.AttrType, attr.AttrVals)
		}
	}
	return modReq, nil
}

func DecodePartialAttribute(p *ber.Packet) (*PartialAttribute, error) {
	var ok bool
	if len(p.Children) != 2 {
		return nil, ErrBadProtocol
	}
	attr := &PartialAttribute{}
	attrs := p.Children[1].Children
	if len(attrs) != 2 {
		return nil, ErrBadProtocol
	}
	attr.AttrType, ok = attrs[0].Value.(string)
	if !ok {
		return nil, ErrBadProtocol
	}
	for _, val := range attrs[1].Children {
		v, ok := val.Value.(string)
		if !ok {
			return nil, ErrBadProtocol
		}
		attr.AttrVals = append(attr.AttrVals, v)
	}
	op, ok := p.Children[0].Value.(int64)
	if !ok {
		return nil, ErrBadProtocol
	}
	attr.op = op
	return attr, nil

}
