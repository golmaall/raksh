package raksh

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

var reqWriteExcludeHeader = map[string]bool{
	"Host": true,
}

func readResponse(br *bufio.Reader, req *http.Request) (resp *http.Response, err error) {
	resp, err = http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusContinue {
		resp, err = http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
	}
	return resp, err
}

type PersistConn struct {
	br       *bufio.Reader
	bw       *bufio.Writer
	cacheKey string
	t        *ProxyTransport
	conn     net.Conn
}

func (pc *PersistConn) close() {
	pc.conn.Close()
}

type ProxyTransport struct {
	// pool of persistent connections. The connections are key'ed by the
	// front-end client's address(ip:port). Also since the Std Library
	// HTTP server implementation serializes the processing of requests
	// from a client in a go-routine, a backend connection is
	// guaranteed to have no contention.
	// Further, the ConnState Hook is invoked in the context of this
	// goroutine, so cleanup is relatively simpler.
	// In the event of a backend connection error, close the connection.
	// A future request would result in a new connection being setup and
	// the system recovering.
	idleMu    sync.Mutex
	idleConns map[string]*PersistConn
}

// Called by the proxy to notify that the frontend
// client has closed its connection.
// The transport implemenation can use this to cleanup
// its state, if any
func (t *ProxyTransport) ClientClose(remote string) {

	// We dont return an error if there is no backend connection, since
	// a. the connection is setup on the first request and the client
	//    can close before sending out a request.
	// b. the backend connection may have closed due to error.. in this case
	//    again, there is no idleConn sitting around.
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	if pconn, ok := t.idleConns[remote]; ok {
		pconn.close()
		delete(t.idleConns, remote)
		return
	}
	return
}

func (t *ProxyTransport) ReadResponse(pconn *PersistConn, req *http.Request) (resp *http.Response, err error) {
	resp, err = readResponse(pconn.br, req)
	if err != nil {
		pconn.close()
		return nil, err
	}
	return resp, nil
}

// return the connection back to the pool.
func (t *ProxyTransport) PutConnection(pconn *PersistConn) error {
	t.idleMu.Lock()
	defer t.idleMu.Unlock()

	key := pconn.cacheKey
	t.idleConns[key] = pconn
	return nil
}

type responseAndError struct {
	res *http.Response
	err error
}

type connCloser struct {
	io.ReadCloser
	conn net.Conn
}

func (this *connCloser) Close() error {
	this.conn.Close()
	return this.ReadCloser.Close()
}

// canonicalAddr returns url.Host but always with a ":port" suffix
func canonicalAddr(url *url.URL) string {
	addr := url.Host

	if !hasPort(addr) {
		if url.Scheme == "http" {
			return addr + ":80"
		} else {
			return addr + ":443"
		}
	}

	return addr
}

func (t *ProxyTransport) dial(req *http.Request) (net.Conn, error) {
	targetAddr := canonicalAddr(req.URL)

	c, err := net.Dial("tcp", targetAddr)

	if err != nil {
		return c, err
	}

	if req.URL.Scheme == "https" {
		c = tls.Client(c, &tls.Config{ServerName: req.URL.Host})

		if err = c.(*tls.Conn).Handshake(); err != nil {
			return nil, err
		}

		if err = c.(*tls.Conn).VerifyHostname(req.URL.Host); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func hasPort(s string) bool {
	return strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
}

func (t *ProxyTransport) NewConnection(req *http.Request, pconn *PersistConn) error {
	conn, err := t.dial(req)
	if err != nil {
		return err
	}
	pconn.conn = conn
	pconn.br = bufio.NewReader(conn)
	pconn.bw = bufio.NewWriter(conn)
	return nil
}

func (t *ProxyTransport) GetConnection(req *http.Request) (*PersistConn, error) {
	t.idleMu.Lock()
	defer t.idleMu.Unlock()

	if t.idleConns == nil {
		t.idleConns = make(map[string]*PersistConn)
	}
	key := req.RemoteAddr
	if pconn, ok := t.idleConns[key]; ok {
		delete(t.idleConns, key)
		return pconn, nil
	}
	pconn := &PersistConn{
		t:        t,
		cacheKey: req.RemoteAddr,
	}
	err := t.NewConnection(req, pconn)
	if err != nil {
		return nil, err
	}
	return pconn, nil
}

func (t *ProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, errors.New("http: nil Request.URL")
	}
	if req.Header == nil {
		return nil, errors.New("http: nil Request Header")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return nil, errors.New("http: unsupported protocol scheme")
	}
	if req.URL.Host == "" {
		return nil, errors.New("http: no Host in request URL")
	}

	conn, err := t.dial(req)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	readDone := make(chan responseAndError, 1)
	writeDone := make(chan error, 1)

	//Write the request
	go func() {
		err := req.Write(writer)
		if err == nil {
			writer.Flush()
		}
		writeDone <- err
	}()

	// Read the response
	go func() {
		resp, err := readResponse(reader, req)
		if err != nil {
			readDone <- responseAndError{nil, err}
			return
		}
		resp.Body = &connCloser{resp.Body, conn}
		readDone <- responseAndError{resp, nil}
	}()

	if err = <-writeDone; err != nil {
		return nil, err
	}
	r := <-readDone
	if r.err != nil {
		return nil, r.err
	}
	return r.res, nil
}

func (t *ProxyTransport) Write(pconn *PersistConn, req *http.Request, src []byte) (int, error) {
	for {
		w := pconn.bw
		nw, err := w.Write(src)
		if err == nil {
			return nw, w.Flush()
		}
		if !pconn.shouldRetryRequest(req, err) {
			pconn.close()
			return nw, err
		}
		err = t.NewConnection(req, pconn)
		if err != nil {
			pconn.close()
			return nw, err
		}
	}
}

func (pconn *PersistConn) shouldRetryRequest(req *http.Request, err error) bool {
	if err == ProxyErrMissingHost {
		return false
	}
	if opErr, ok := err.(*net.OpError); ok {
		if opErr.Temporary() == true {
			return true
		}
	}

	// TODO: remove this string search once the standard library
	// returns this as a temporary error too..
	errStr := err.Error()
	if strings.Contains(errStr, "use of closed network connection") {
		return true
	}
	return false //conservatively
}

func (t *ProxyTransport) writeHeader(w *bufio.Writer, req *http.Request) error {
	host := req.Host
	if host == "" {
		if req.URL == nil {
			return ProxyErrMissingHost
		}
		host = req.URL.Host
	}

	ruri := req.URL.RequestURI()
	_, err := fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", req.Method, ruri)
	if err != nil {
		return err
	}

	// Header lines
	_, err = fmt.Fprintf(w, "Host: %s\r\n", host)
	if err != nil {
		return err
	}

	// Since this is a proxy, assuming the incoming request should have
	// headers in correct format.
	err = req.Header.WriteSubset(w, reqWriteExcludeHeader)
	if err != nil {
		return err
	}

	_, err = io.WriteString(w, "\r\n")
	if err != nil {
		return err
	}

	// Flush only if there is no body in this request
	if req.ContentLength == 0 && req.Body == nil {
		return w.Flush()
	}
	return nil
}

var ProxyErrMissingHost = errors.New("proxy: Request with no Host or URL set")

func (t *ProxyTransport) WriteHeader(pconn *PersistConn, req *http.Request) error {

	fmt.Printf("Request %s\n", req)
	for {
		err := t.writeHeader(pconn.bw, req)
		if err == nil {
			break
		}
		if !pconn.shouldRetryRequest(req, err) {
			pconn.close()
			return err
		}
		// retryable request. Open a new connection
		err = t.NewConnection(req, pconn)
		if err != nil {
			pconn.close()
			return err
		}
	}
	return nil
}
