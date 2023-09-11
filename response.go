package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

type Response struct {
	MessageID uint64
	Type      ber.Tag
	Code      LDAPResultCode
	Message   string
}

func (res *Response) ToBER() *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, res.MessageID, "Message ID"))
	reponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, res.Type, nil, ApplicationMap[res.Type])
	reponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(res.Code), "resultCode: "))
	reponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	reponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, res.Message, "errorMessage: "))
	responsePacket.AppendChild(reponse)
	return responsePacket
}

func DecodeResponse(p *ber.Packet) (*Response, error) {
	return nil, nil
}
