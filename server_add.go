package ldap

import (
	"context"
	"log"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

func (session *Session) Add(req *ber.Packet, ctx context.Context) LDAPResultCode {
	_, span := otel.Tracer("LDAP").Start(ctx, "Add")
	defer span.End()
	addReq, err := DecodeAddRequest(req)
	if err != nil {
		return err.(*Error).ResultCode
	}
	resultCode, err := session.handler.Add(session.boundDN, *addReq, session.conn)
	if err != nil {
		log.Printf("AddFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}
