package ldap

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestRequest(t *testing.T) {
	bind := &BindRequest{
		Simple: &SimpleAuth{
			UserName: "test",
			Password: "foo",
		},
	}

	p := bind.ToBER()

	res, err := DecodeBindRequest(p)
	if err != nil {
		ber.PrintPacket(p)
		t.Fatalf("bad packet: %v", err)
	}
	if res.Simple.UserName != bind.Simple.UserName {
		t.Fatalf("request UserName was wrong%v", res.Simple.UserName)
	}
	if res.Simple.Password != bind.Simple.Password {
		t.Fatalf("request UserName was wrong%v", res.Simple.UserName)
	}
}
