package ldap

import (
	"context"
	"log"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

func (session *Session) Modify(req *ber.Packet, ctx context.Context) LDAPResultCode {
	_, span := otel.Tracer("LDAP").Start(ctx, "Modify")
	defer span.End()
	modReq, err := DecodeModifyRequest(req)
	if err != nil {
		return err.(*Error).ResultCode
	}
	resultCode, err := session.handler.Modify(session.boundDN, *modReq, session.conn)
	if err != nil {
		log.Printf("ModifyFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}
