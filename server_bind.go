package ldap

import (
	"context"
	"log"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

func (session *Session) Bind(req *ber.Packet, fn Binder, ctx context.Context) LDAPResultCode {
	_, span := otel.Tracer("LDAP").Start(context.Background(), "Bind")
	defer span.End()
	// we only support ldapv3
	ldapVersion, ok := req.Children[0].Value.(int64)
	if !ok {
		return LDAPResultProtocolError
	}
	if ldapVersion != 3 {
		log.Printf("Unsupported LDAP version: %d", ldapVersion)
		return LDAPResultInappropriateAuthentication
	}

	// auth types
	bindDN, ok := req.Children[1].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	bindAuth := req.Children[2]
	switch bindAuth.Tag {
	default:
		log.Print("Unknown LDAP authentication method")
		return LDAPResultInappropriateAuthentication
	case LDAPBindAuthSimple:
		if len(req.Children) != 3 {
			log.Print("Simple bind request has wrong # children.  len(req.Children) != 3")
			return LDAPResultInappropriateAuthentication
		}
		resultCode, err := fn.Bind(bindDN, bindAuth.Data.String(), session.conn)
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
