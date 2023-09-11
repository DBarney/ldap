package ldap

import (
	"errors"

	ber "github.com/go-asn1-ber/asn1-ber"
)

var (
	ErrBadProtocol                 = NewError(LDAPResultProtocolError, errors.New("unexpected error parsing packet"))
	ErrInappropriateAuthentication = NewError(LDAPResultInappropriateAuthentication, errors.New("unexpected error parsing packet"))
)

type SimpleAuth struct {
	UserName string
	Password string
}

type BindRequest struct {
	Simple *SimpleAuth
}

func (bind *BindRequest) ToBER() *ber.Packet {
	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "Version"))

	if bind.Simple != nil {
		bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, bind.Simple.UserName, "User Name"))
		bindRequest.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, LDAPBindAuthSimple, bind.Simple.Password, "Password"))
	}

	return bindRequest
}

func DecodeBindRequest(p *ber.Packet) (*BindRequest, error) {
	// check the ClassType
	if p.ClassType != ber.ClassApplication {
		return nil, ErrBadProtocol
	}
	if p.Tag != ApplicationBindRequest {
		return nil, ErrBadProtocol
	}
	if len(p.Children) < 3 {
		return nil, ErrInappropriateAuthentication
	}
	// we only support ldapv3
	ldapVersion, ok := p.Children[0].Value.(int64)
	if !ok {
		return nil, ErrBadProtocol
	}
	if ldapVersion != 3 {
		return nil, ErrInappropriateAuthentication
	}

	// auth types
	bindDN, ok := p.Children[1].Value.(string)
	if !ok {
		return nil, ErrBadProtocol
	}

	bindAuth := p.Children[2]
	switch bindAuth.Tag {
	default:
		return nil, ErrInappropriateAuthentication
	case LDAPBindAuthSimple:
		return &BindRequest{
			Simple: &SimpleAuth{
				UserName: bindDN,
				Password: bindAuth.Data.String(),
			},
		}, nil
	case LDAPBindAuthSASL:
		return nil, ErrInappropriateAuthentication
	}
}
