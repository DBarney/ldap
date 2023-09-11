package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

type ServerSearchResult struct {
	Entries    []*Entry
	Referrals  []string
	Controls   []Control
	ResultCode LDAPResultCode
}

//
type Server struct {
	handler     Handler
	quit        chan bool
	EnforceLDAP bool
}

type Session struct {
	boundDN     string
	conn        net.Conn
	server      *Server
	handler     Handler
	enforceLDAP bool
}

//
func NewServer() *Server {
	s := new(Server)
	s.quit = make(chan bool)

	s.handler = NewRouter()
	return s
}

func (server *Server) Handler(h Handler) {
	server.handler = h
}

func (server *Server) ListenAndServeTLS(listenString string, certFile string, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConfig.ServerName = "localhost"
	ln, err := tls.Listen("tcp", listenString, &tlsConfig)
	if err != nil {
		return err
	}
	return server.Serve(ln)
}

func (server *Server) ListenAndServe(listenString string) error {
	ln, err := net.Listen("tcp", listenString)
	if err != nil {
		return err
	}
	return server.Serve(ln)
}

func (server *Server) Serve(ln net.Listener) error {
	defer close(server.quit)

	conChan := make(chan net.Conn)
	errChan := make(chan error)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				errChan <- err
				return
			}
			conChan <- conn
		}
	}()

	ctx, span := otel.Tracer("LDAP").Start(context.Background(), "Listen")
	defer span.End()

	for {
		select {
		case c := <-conChan:
			go server.handleConnection(c, ctx)
		case err := <-errChan:
			return err
		case <-server.quit:
			ln.Close()
			return nil
		}
	}
}

//Close closes the underlying net.Listener, and waits for confirmation
func (server *Server) Close() {
	server.quit <- true
	<-server.quit
}

//
func (server *Server) handleConnection(conn net.Conn, ctx context.Context) {
	ctx, span := otel.Tracer("LDAP").Start(ctx, "Connection")
	defer span.End()

	session := &Session{
		conn:        conn,
		server:      server,
		handler:     server.handler,
		boundDN:     "",
		enforceLDAP: server.EnforceLDAP,
	}

	for {
		// read incoming LDAP packet
		packet, err := ber.ReadPacket(conn)
		//start := time.Now()
		if err == io.EOF || err == io.ErrUnexpectedEOF { // Client closed connection
			break
		} else if err != nil {
			log.Printf("handleConnection ber.ReadPacket ERROR: %s", err.Error())
			break
		}
		responsePacket := session.handleCommand(packet, ctx)
		if responsePacket != nil {
			_, err := conn.Write(responsePacket.Bytes())
			if err != nil {
				fmt.Println("unable to write response", err)
			}
		}
	}
}

func (session *Session) handleCommand(packet *ber.Packet, ctx context.Context) (p *ber.Packet) {
	ctx, span := otel.Tracer("LDAP").Start(ctx, "Command")
	defer span.End()

	req, err := DecodeRequest(packet)
	if err != nil {
		session.conn.Close()
		fmt.Println(err)
		return nil
	}

	command := req.Command

	res := &Response{
		MessageID: req.MessageID,
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)
			// res.Type is already set correctly before the operation
			// is handled, this way we can send an error back over
			// the socket with the correct response type set
			res.Code = LDAPResultOperationsError
			res.Message = LDAPResultCodeMap[res.Code]
			p = res.ToBER()
		}
	}()

	// dispatch the LDAP operation
	switch command.Tag {
	default:
		res.Type = ApplicationAddResponse
		res.Code = LDAPResultOperationsError
		res.Message = "Unsupported operation"

	case ApplicationBindRequest:
		res.Type = ApplicationBindResponse
		res.Code = session.Bind(command, ctx)

	case ApplicationSearchRequest:
		res.Type = ApplicationSearchResultDone
		res.Code = LDAPResultCode(LDAPResultSuccess)
		if err := session.Search(command, req.Controls, req.MessageID, ctx); err != nil {
			log.Printf("handleSearchRequest error %s", err.Error())
			e := err.(*Error)
			res.Code = e.ResultCode
		}

	case ApplicationUnbindRequest:
		session.boundDN = "" // anything else?
		return nil
	case ApplicationExtendedRequest:
		res.Type = ApplicationExtendedResponse
		res.Code = session.Extended(command, ctx)

	case ApplicationAbandonRequest:
		session.Abandon(command, ctx)
		return nil

	case ApplicationAddRequest:
		res.Type = ApplicationAddResponse
		res.Code = session.Add(command, ctx)

	case ApplicationModifyRequest:
		res.Type = ApplicationModifyResponse
		res.Code = session.Modify(command, ctx)

	case ApplicationDelRequest:
		res.Type = ApplicationDelResponse
		res.Code = session.Delete(command, ctx)

	case ApplicationModifyDNRequest:
		res.Type = ApplicationModifyDNResponse
		res.Code = session.ModifyDN(command, ctx)

	case ApplicationCompareRequest:
		res.Type = ApplicationCompareResponse
		res.Code = session.Compare(command, ctx)
	}
	res.Message = LDAPResultCodeMap[res.Code]

	return res.ToBER()
}
