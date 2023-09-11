package ldap

import (
	"context"
	"log"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

func (session *Session) ModifyDN(req *ber.Packet, ctx context.Context) LDAPResultCode {
	_, span := otel.Tracer("LDAP").Start(ctx, "ModifyDN")
	defer span.End()
	mdnReq, err := DecodeModifyDNRequest(req)
	if err != nil {
		return err.(*Error).ResultCode
	}
	resultCode, err := session.handler.ModifyDN(session.boundDN, *mdnReq, session.conn)
	if err != nil {
		log.Printf("ModifyDN Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}
