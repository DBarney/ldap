package ldap

import (
	"context"
	"log"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

func (session *Session) Compare(req *ber.Packet, ctx context.Context) LDAPResultCode {
	_, span := otel.Tracer("LDAP").Start(ctx, "Compare")
	defer span.End()
	compReq, err := DecodeCompareRequest(req)
	if err != nil {
		return err.(*Error).ResultCode
	}
	resultCode, err := session.handler.Compare(session.boundDN, *compReq, session.conn)
	if err != nil {
		log.Printf("CompareFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}
