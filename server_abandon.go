package ldap

import (
	"context"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

func (session *Session) Abandon(req *ber.Packet, ctx context.Context) error {
	_, span := otel.Tracer("LDAP").Start(ctx, "Abandon")
	defer span.End()
	err := session.handler.Abandon(session.boundDN, session.conn)
	return err
}
