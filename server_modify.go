package ldap

import (
	"log"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func HandleAddRequest(req *ber.Packet, boundDN string, fn Adder, conn net.Conn) (resultCode LDAPResultCode) {
	if len(req.Children) != 2 {
		return LDAPResultProtocolError
	}
	var ok bool
	addReq := AddRequest{}
	addReq.dn, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	addReq.attributes = []Attribute{}
	for _, attr := range req.Children[1].Children {
		if len(attr.Children) != 2 {
			return LDAPResultProtocolError
		}

		a := Attribute{}
		a.attrType, ok = attr.Children[0].Value.(string)
		if !ok {
			return LDAPResultProtocolError
		}
		a.attrVals = []string{}
		for _, val := range attr.Children[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				return LDAPResultProtocolError
			}
			a.attrVals = append(a.attrVals, v)
		}
		addReq.attributes = append(addReq.attributes, a)
	}
	resultCode, err := fn.Add(boundDN, addReq, conn)
	if err != nil {
		log.Printf("AddFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleDeleteRequest(req *ber.Packet, boundDN string, fn Deleter, conn net.Conn) (resultCode LDAPResultCode) {
	deleteDN := ber.DecodeString(req.Data.Bytes())
	resultCode, err := fn.Delete(boundDN, deleteDN, conn)
	if err != nil {
		log.Printf("DeleteFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleModifyRequest(req *ber.Packet, boundDN string, fn Modifier, conn net.Conn) (resultCode LDAPResultCode) {
	if len(req.Children) != 2 {
		return LDAPResultProtocolError
	}
	var ok bool
	modReq := ModifyRequest{}
	modReq.Dn, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	for _, change := range req.Children[1].Children {
		if len(change.Children) != 2 {
			return LDAPResultProtocolError
		}
		attr := PartialAttribute{}
		attrs := change.Children[1].Children
		if len(attrs) != 2 {
			return LDAPResultProtocolError
		}
		attr.AttrType, ok = attrs[0].Value.(string)
		if !ok {
			return LDAPResultProtocolError
		}
		for _, val := range attrs[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				return LDAPResultProtocolError
			}
			attr.AttrVals = append(attr.AttrVals, v)
		}
		op, ok := change.Children[0].Value.(int64)
		if !ok {
			return LDAPResultProtocolError
		}
		switch op {
		default:
			log.Printf("Unrecognized Modify attribute %d", op)
			return LDAPResultProtocolError
		case AddAttribute:
			modReq.Add(attr.AttrType, attr.AttrVals)
		case DeleteAttribute:
			modReq.Delete(attr.AttrType, attr.AttrVals)
		case ReplaceAttribute:
			modReq.Replace(attr.AttrType, attr.AttrVals)
		}
	}
	resultCode, err := fn.Modify(boundDN, modReq, conn)
	if err != nil {
		log.Printf("ModifyFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleCompareRequest(req *ber.Packet, boundDN string, fn Comparer, conn net.Conn) (resultCode LDAPResultCode) {
	if len(req.Children) != 2 {
		return LDAPResultProtocolError
	}
	var ok bool
	compReq := CompareRequest{}
	compReq.dn, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	ava := req.Children[1]
	if len(ava.Children) != 2 {
		return LDAPResultProtocolError
	}
	attr, ok := ava.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	val, ok := ava.Children[1].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	compReq.ava = []AttributeValueAssertion{AttributeValueAssertion{attr, val}}
	resultCode, err := fn.Compare(boundDN, compReq, conn)
	if err != nil {
		log.Printf("CompareFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleExtendedRequest(req *ber.Packet, boundDN string, fn Extender, conn net.Conn) (resultCode LDAPResultCode) {
	if len(req.Children) != 1 && len(req.Children) != 2 {
		return LDAPResultProtocolError
	}
	name := ber.DecodeString(req.Children[0].Data.Bytes())
	var val string
	if len(req.Children) == 2 {
		val = ber.DecodeString(req.Children[1].Data.Bytes())
	}
	extReq := ExtendedRequest{name, val}
	resultCode, err := fn.Extended(boundDN, extReq, conn)
	if err != nil {
		log.Printf("ExtendedFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleAbandonRequest(req *ber.Packet, boundDN string, fn Abandoner, conn net.Conn) error {
	err := fn.Abandon(boundDN, conn)
	return err
}

func HandleModifyDNRequest(req *ber.Packet, boundDN string, fn ModifyDNr, conn net.Conn) (resultCode LDAPResultCode) {
	if len(req.Children) != 3 && len(req.Children) != 4 {
		return LDAPResultProtocolError
	}
	var ok bool
	mdnReq := ModifyDNRequest{}
	mdnReq.dn, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	mdnReq.newrdn, ok = req.Children[1].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	mdnReq.deleteoldrdn, ok = req.Children[2].Value.(bool)
	if !ok {
		return LDAPResultProtocolError
	}
	if len(req.Children) == 4 {
		mdnReq.newSuperior, ok = req.Children[3].Value.(string)
		if !ok {
			return LDAPResultProtocolError
		}
	}
	resultCode, err := fn.ModifyDN(boundDN, mdnReq, conn)
	if err != nil {
		log.Printf("ModifyDN Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}
