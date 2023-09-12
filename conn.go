// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"sync/atomic"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type messagePacket struct {
	MessageID uint64
	Packet    *ber.Packet
	Channel   chan *ber.Packet
}

// Conn represents an LDAP Connection
type Conn struct {
	conn        net.Conn
	isTLS       bool
	Debug       debugging
	chanResults map[uint64]chan *ber.Packet
	chanMessage chan *messagePacket
	messageID   uint64
	chanDone    chan struct{}
	chanClosed  chan struct{}
}

// Dial connects to the given address on the given network using net.Dial
// and then returns a new Conn for the connection.
func Dial(network, addr string) (*Conn, error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewConn(c)
	conn.start()
	return conn, nil
}

// DialTimeout connects to the given address on the given network using net.DialTimeout
// and then returns a new Conn for the connection. Acts like Dial but takes a timeout.
func DialTimeout(network, addr string, timeout time.Duration) (*Conn, error) {
	c, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewConn(c)
	conn.start()
	return conn, nil
}

// DialTLS connects to the given address on the given network using tls.Dial
// and then returns a new Conn for the connection.
func DialTLS(network, addr string, config *tls.Config) (*Conn, error) {
	c, err := tls.Dial(network, addr, config)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewConn(c)
	conn.isTLS = true
	conn.start()
	return conn, nil
}

// DialTLSDialer connects to the given address on the given network using tls.DialWithDialer
// and then returns a new Conn for the connection.
func DialTLSDialer(network, addr string, config *tls.Config, dialer *net.Dialer) (*Conn, error) {
	c, err := tls.DialWithDialer(dialer, network, addr, config)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewConn(c)
	conn.isTLS = true
	conn.start()
	return conn, nil
}

// NewConn returns a new Conn using conn for network I/O.
func NewConn(conn net.Conn) *Conn {
	return &Conn{
		conn:        conn,
		messageID:   1,
		chanMessage: make(chan *messagePacket, 0),
		chanResults: map[uint64]chan *ber.Packet{},
		chanDone:    make(chan struct{}, 0),
		chanClosed:  make(chan struct{}, 0),
	}
}

func (l *Conn) start() {
	go l.reader()
	go l.processMessages()
}

// Close closes the connection.
func (l *Conn) Close() {
	select {
	case l.chanDone <- struct{}{}:
		<-l.chanClosed
	case <-l.chanClosed:
	}
}

// Returns the next available messageID
func (l *Conn) nextMessageID() uint64 {
	return atomic.AddUint64(&l.messageID, 1)
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
// TODO: this can seriously screw up the req/response flow if start has already been called
func (l *Conn) StartTLS(config *tls.Config) error {
	messageID := l.nextMessageID()

	if l.isTLS {
		return NewError(ErrorNetwork, errors.New("ldap: already encrypted"))
	}

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Start TLS")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	packet.AppendChild(request)
	l.Debug.PrintPacket(packet)

	_, err := l.conn.Write(packet.Bytes())
	if err != nil {
		return NewError(ErrorNetwork, err)
	}

	packet, err = ber.ReadPacket(l.conn)
	if err != nil {
		return NewError(ErrorNetwork, err)
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return err
		}
		ber.PrintPacket(packet)
	}

	if packet.Children[1].Children[0].Value.(uint64) == 0 {
		conn := tls.Client(l.conn, config)
		l.isTLS = true
		l.conn = conn
	}

	return nil
}

func (l *Conn) sendMessage(packet *ber.Packet) (chan *ber.Packet, error) {
	out := make(chan *ber.Packet)
	message := &messagePacket{
		MessageID: packet.Children[0].Value.(uint64),
		Packet:    packet,
		Channel:   out,
	}
	return out, l.sendProcessMessage(message)
}

func (l *Conn) finishMessage(messageID uint64) {
	//TODO: thread safe
	close(l.chanResults[messageID])
	delete(l.chanResults, messageID)
}

func (l *Conn) sendProcessMessage(message *messagePacket) error {
	select {
	case <-l.chanClosed:
		return NewError(ErrorNetwork, errors.New("ldap: connection closed"))
	case l.chanMessage <- message:
		return nil
	}
}

func (l *Conn) processMessages() {
	defer func() {
		close(l.chanClosed)
		for messageID, channel := range l.chanResults {
			l.Debug.Printf("Closing channel for MessageID %d", messageID)
			close(channel)
		}
		close(l.chanDone)
	}()

	for {
		select {
		case <-l.chanDone:
			l.Debug.Printf("Shutting down - quit message received")
			err := l.conn.Close()
			if err != nil {
				log.Print(err)
			}
			return
		case messagePacket := <-l.chanMessage:

			// Add to message list and write to network
			l.Debug.Printf("Sending message %d", messagePacket.MessageID)
			l.chanResults[messagePacket.MessageID] = messagePacket.Channel

			buf := messagePacket.Packet.Bytes()
			_, err := l.conn.Write(buf)
			if err != nil {
				l.Debug.Printf("Error Sending Message: %s", err.Error())
				return
			}
		}
	}
}

func (l *Conn) reader() {
	defer func() {
		l.Close()
	}()

	for {
		packet, err := ber.ReadPacket(l.conn)
		if err != nil {
			l.Debug.Printf("reader: %s", err.Error())
			return
		}
		addLDAPDescriptions(packet)
		messageID := uint64(packet.Children[0].Value.(int64))

		// TODO: thread safe
		chanResult, ok := l.chanResults[messageID]
		if !ok {
			log.Printf("Received unexpected message %d", messageID)
			ber.PrintPacket(packet)
			continue
		}
		select {
		case <-l.chanClosed:
			return
		case chanResult <- packet:
		}

	}
}
