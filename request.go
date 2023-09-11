package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

type Request struct {
	MessageID uint64
	Command   *ber.Packet
	Controls  []Control
}

func (req *Request) ToBER() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, req.MessageID, "MessageID"))
	packet.AppendChild(req.Command)
	if req.Controls != nil {
		packet.AppendChild(encodeControls(req.Controls))

	}
	return packet
}

func DecodeRequest(p *ber.Packet) (*Request, error) {
	req := &Request{}
	// sanity check this packet
	if len(p.Children) < 2 {
		return nil, ErrBadProtocol
	}

	// check the message ID
	messageID64, ok := p.Children[0].Value.(int64)
	if !ok {
		return nil, ErrBadProtocol
	}
	req.MessageID = uint64(messageID64)
	req.Command = p.Children[1]
	// handle controls if present
	if len(p.Children) == 3 {
		for _, child := range p.Children[2].Children {
			req.Controls = append(req.Controls, DecodeControl(child))
		}
	}

	return req, nil
}
