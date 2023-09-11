package ldap

import (
	"context"
	"log"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

func (session *Session) Bind(p *ber.Packet, ctx context.Context) LDAPResultCode {
	_, span := otel.Tracer("LDAP").Start(context.Background(), "Bind")
	defer span.End()
	req, err := DecodeBindRequest(p)
	if err != nil {
		return err.(*Error).ResultCode
	}

	// We only support Simple Authentication currently
	if req.Simple == nil {
		return LDAPResultOperationsError
	}

	resultCode, err := session.handler.Bind(req.Simple.UserName, req.Simple.Password, session.conn)
	if err != nil {
		log.Printf("Bind Error %s", err.Error())
		return LDAPResultOperationsError
	}
	session.boundDN = req.Simple.UserName
	return resultCode
}
