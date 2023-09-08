package ldap

import (
	"log"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type bindReq struct {
	Type     ber.Tag
	User     string
	Password string
}

func (b *bindReq) id() ber.Tag {
	return ApplicationBindResponse
}

func (b *bindReq) fromPacket(p *ber.Packet) error {
	// we only support ldapv3
	ldapVersion, ok := req.Children[0].Value.(int64)
	if !ok {
		return LDAPResultProtocolError
	}
	if ldapVersion != 3 {
		return LDAPResultInappropriateAuthentication
	}

	// auth types
	bindDN, ok := req.Children[1].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	b.User = bindDN
	bindAuth := req.Children[2]
	switch bindAuth.Tag {
	case LDAPBindAuthSimple:
		if len(req.Children) != 3 {
			return LDAPResultInappropriateAuthentication
		}
		b.Password = bindAuth.Data.String()
	default:
		return LDAPResultInappropriateAuthentication
	}
}

func (b *bindReq) toPacket() *ber.Packet {
	switch m.Type {
	case LDAPAuthSimple:
		return newApplication(ApplicationBindRequest, "Bind Request",
			newInteger(3, "Version"),
			newString(b.user, "User Name"),
			newContextString(0, b.password, "Password"))

	}
}

func HandleBindRequest(req *ber.Packet, fns map[string]Binder, conn net.Conn) (resultCode LDAPResultCode) {
	defer func() {
		if r := recover(); r != nil {
			resultCode = LDAPResultOperationsError
		}
	}()

	switch bindAuth.Tag {
	default:
		log.Print("Unknown LDAP authentication method")
		return LDAPResultInappropriateAuthentication
	case LDAPBindAuthSimple:
		if len(req.Children) != 3 {
			log.Print("Simple bind request has wrong # children.  len(req.Children) != 3")
			return LDAPResultInappropriateAuthentication
		}
		fnNames := []string{}
		for k := range fns {
			fnNames = append(fnNames, k)
		}
		fn := routeFunc(bindDN, fnNames)
		resultCode, err := fns[fn].Bind(bindDN, bindAuth.Data.String(), conn)
		if err != nil {
			log.Printf("BindFn Error %s", err.Error())
			return LDAPResultOperationsError
		}
		return resultCode
	case LDAPBindAuthSASL:
		log.Print("SASL authentication is not supported")
		return LDAPResultInappropriateAuthentication
	}
	return LDAPResultOperationsError
}

func encodeBindResponse(messageID uint64, ldapResultCode LDAPResultCode) *ber.Packet {
	return newLDAPResponse(messageID,
		newApplication(ApplicationBindResponse, "Bind Response",
			newEnum(uint64(ldapResultCode), "resultCode: "),
			newString("", "matchedDN: "),
			newString("", "errorMessage: "),
		),
	)
}
