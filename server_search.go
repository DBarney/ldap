package ldap

import (
	"context"
	"errors"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

func (session *Session) Search(req *ber.Packet, controls []Control, messageID uint64, ctx context.Context) error {
	_, span := otel.Tracer("LDAP").Start(ctx, "Search")
	defer span.End()
	searchReq, err := DecodeSearchRequest(req)
	if err != nil {
		return err
	}
	searchReq.Controls = controls

	filterPacket, err := CompileFilter(searchReq.Filter)
	if err != nil {
		return NewError(LDAPResultOperationsError, err)
	}

	searchResp, err := session.handler.Search(session.boundDN, *searchReq, session.conn)
	if err != nil {
		return NewError(searchResp.ResultCode, err)
	}

	if session.enforceLDAP {
		if searchReq.DerefAliases != NeverDerefAliases { // [-a {never|always|search|find}
			// TODO: Server DerefAliases not supported: RFC4511 4.5.1.3
		}
		if searchReq.TimeLimit > 0 {
			// TODO: Server TimeLimit not implemented
		}
	}

	i := 0
	searchReqBaseDNLower := strings.ToLower(searchReq.BaseDN)
	for _, entry := range searchResp.Entries {
		if session.enforceLDAP {
			// filter
			keep, resultCode := ServerApplyFilter(filterPacket, entry)
			if resultCode != LDAPResultSuccess {
				return NewError(resultCode, errors.New("ServerApplyFilter error"))
			}
			if !keep {
				continue
			}

			// constrained search scope
			switch searchReq.Scope {
			case ScopeWholeSubtree: // The scope is constrained to the entry named by baseObject and to all its subordinates.
			case ScopeBaseObject: // The scope is constrained to the entry named by baseObject.
				if strings.ToLower(entry.DN) != searchReqBaseDNLower {
					continue
				}
			case ScopeSingleLevel: // The scope is constrained to the immediate subordinates of the entry named by baseObject.
				entryDNLower := strings.ToLower(entry.DN)
				parts := strings.Split(entryDNLower, ",")
				if len(parts) < 2 && entryDNLower != searchReqBaseDNLower {
					continue
				}
				if dnSuffix := strings.Join(parts[1:], ","); dnSuffix != searchReqBaseDNLower {
					continue
				}
			}

			// filter attributes
			entry, err = filterAttributes(entry, searchReq.Attributes)
			if err != nil {
				return NewError(LDAPResultOperationsError, err)
			}

			// size limit
			if searchReq.SizeLimit > 0 && i >= searchReq.SizeLimit {
				break
			}
			i++
		}

		// respond
		responsePacket := encodeSearchResponse(messageID, *searchReq, entry)
		_, err := session.conn.Write(responsePacket.Bytes())
		if err != nil {
			return NewError(LDAPResultOperationsError, err)
		}
	}
	return nil
}

/////////////////////////
func filterAttributes(entry *Entry, attributes []string) (*Entry, error) {
	// only return requested attributes
	newAttributes := []*EntryAttribute{}

	if len(attributes) > 1 || (len(attributes) == 1 && len(attributes[0]) > 0) {
		for _, attr := range entry.Attributes {
			attrNameLower := strings.ToLower(attr.Name)
			for _, requested := range attributes {
				requestedLower := strings.ToLower(requested)
				// You can request the directory server to return operational attributes by adding + (the plus sign) in your ldapsearch command.
				// "+supportedControl" is treated as an operational attribute
				if strings.HasPrefix(attrNameLower, "+") {
					if requestedLower == "+" || attrNameLower == "+"+requestedLower {
						newAttributes = append(newAttributes, &EntryAttribute{attr.Name[1:], attr.Values})
						break
					}
				} else {
					if requested == "*" || attrNameLower == requestedLower {
						newAttributes = append(newAttributes, attr)
						break
					}
				}
			}
		}
	} else {
		// remove operational attributes
		for _, attr := range entry.Attributes {
			if !strings.HasPrefix(attr.Name, "+") {
				newAttributes = append(newAttributes, attr)
			}
		}
	}
	entry.Attributes = newAttributes

	return entry, nil
}

/////////////////////////
func encodeSearchResponse(messageID uint64, req SearchRequest, res *Entry) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	searchEntry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
	searchEntry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, res.DN, "Object Name"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes:")
	for _, attribute := range res.Attributes {
		attrs.AppendChild(encodeSearchAttribute(attribute.Name, attribute.Values))
	}

	searchEntry.AppendChild(attrs)
	responsePacket.AppendChild(searchEntry)

	return responsePacket
}

func encodeSearchAttribute(name string, values []string) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Attribute Name"))

	valuesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Values")
	for _, value := range values {
		valuesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Attribute Value"))
	}

	packet.AppendChild(valuesPacket)

	return packet
}
