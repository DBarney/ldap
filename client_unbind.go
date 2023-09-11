// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func (l *Conn) Unbind() error {
	defer l.Close()
	unbind := &UnbindRequest{}
	messageID := l.nextMessageID()
	req := Request{
		MessageID: messageID,
		Command:   unbind.ToBER(),
	}
	packet := req.ToBER()

	if l.Debug {
		ber.PrintPacket(packet)
	}

	channel, err := l.sendMessage(packet)
	if err != nil {
		return err
	}
	if channel == nil {
		return NewError(ErrorNetwork, errors.New("ldap: could not send message"))
	}
	defer l.finishMessage(messageID)

	packet = <-channel
	if packet == nil {
		return NewError(ErrorNetwork, errors.New("ldap: could not retrieve response"))
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return err
		}
		ber.PrintPacket(packet)
	}

	resultCode, resultDescription := getLDAPResultCode(packet)
	if resultCode != 0 {
		return NewError(resultCode, errors.New(resultDescription))
	}

	return nil
}
