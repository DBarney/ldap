package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

func newLDAPResponse(messageID uint64, children ...*ber.Packet) *ber.Packet {
	resp := newSequence("LDAP Response", newInteger(messageID, "MessageID"))
	return addChildren(resp, children)
}

func newLDAPRequest(messageID uint64, children ...*ber.Packet) *ber.Packet {
	resp := newSequence("LDAP Request", newInteger(messageID, "MessageID"))
	return addChildren(resp, children)
}

func newSequence(msg string, children ...*ber.Packet) *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, msg)
	return addChildren(seq, children)
}

func newApplication(item ber.Tag, msg string, children ...*ber.Packet) *ber.Packet {
	app := ber.Encode(ber.ClassApplication, ber.TypeConstructed, item, nil, msg)
	return addChildren(app, children)
}

func addChildren(packet *ber.Packet, children []*ber.Packet) *ber.Packet {
	for _, child := range children {
		packet.AppendChild(child)
	}
	return packet
}

func newString(value, msg string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, msg)
}
func newContextString(item ber.Tag, value, msg string) *ber.Packet {
	return ber.NewString(ber.ClassContext, ber.TypePrimitive, item, value, msg)
}
func newInteger(value interface{}, msg string) *ber.Packet {
	return ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, value, msg)
}
func newBool(value bool, msg string) *ber.Packet {
	return ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, value, msg)
}

func newEnum(value interface{}, msg string) *ber.Packet {
	return ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, value, msg)
}
