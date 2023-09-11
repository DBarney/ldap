package ldap

import (
	"context"
	"log"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

func (session *Session) Extended(req *ber.Packet, ctx context.Context) LDAPResultCode {
	_, span := otel.Tracer("LDAP").Start(ctx, "Extend")
	defer span.End()
	extReq, err := DecodeExtendedRequest(req)
	if err != nil {
		return err.(*Error).ResultCode
	}
	resultCode, err := session.handler.Extended(session.boundDN, *extReq, session.conn)
	if err != nil {
		log.Printf("ExtendedFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}
