package ldap

import (
	"context"
	"log"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

func (session *Session) Delete(req *ber.Packet, ctx context.Context) LDAPResultCode {
	_, span := otel.Tracer("LDAP").Start(ctx, "Delete")
	defer span.End()
	del, err := DecodeDeleteRequest(req)
	if err != nil {
		return err.(*Error).ResultCode
	}
	resultCode, err := session.handler.Delete(session.boundDN, del.dn, session.conn)
	if err != nil {
		log.Printf("DeleteFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}
