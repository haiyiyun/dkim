package dkim

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/mail"
	"regexp"
	"strings"
)

const (
	SignatureHeaderKey = "DKIM-Signature"
)

var StdSignableHeaders = []string{
	"Cc",
	"Content-Type",
	"Date",
	"From",
	"Reply-To",
	"Subject",
	"To",
	SignatureHeaderKey,
}

var headerRelaxRx = regexp.MustCompile(`\s+`)

type DKIM struct {
	signableHeaders []string
	conf            Conf
	privateKey      *rsa.PrivateKey
}

func New(conf Conf, keyPEM []byte) (d *DKIM, err error) {
	err = conf.Validate()
	if err != nil {
		return
	}
	if len(keyPEM) == 0 {
		return nil, errors.New("invalid key PEM data")
	}
	dkim := &DKIM{
		signableHeaders: StdSignableHeaders,
		conf:            conf,
	}
	der, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(der.Bytes)
	if err != nil {
		return nil, err
	}
	dkim.privateKey = key

	return dkim, nil
}

func (d *DKIM) canonicalBody(msg *mail.Message) []byte {
	/* if msg == nil { */
	/* 	return []byte("") */
	/* } */

	buf := new(bytes.Buffer)
	if msg.Body != nil {
		buf.ReadFrom(msg.Body)
	}
	body := buf.Bytes()

	if d.conf.RelaxedBody() {
		if len(body) == 0 {
			return nil
		}
		// Reduce WSP sequences to single WSP
		rx := regexp.MustCompile(`[ \t]+`)
		body = rx.ReplaceAll(body, []byte(" "))

		// Ignore all whitespace at end of lines.
		// Implementations MUST NOT remove the CRLF
		// at the end of the line
		rx2 := regexp.MustCompile(`\s?(\r\n|\n)`)
		body = rx2.ReplaceAll(body, []byte("\r\n"))
	} else {
		if len(body) == 0 {
			return []byte("\r\n")
		}
	}

	// Ignore all empty lines at the end of the message body
	rx3 := regexp.MustCompile(`[ \r\n]*\z`)
	body = rx3.ReplaceAll(body, []byte(""))

	return append(body, '\r', '\n')
}

func (d *DKIM) canonicalBodyHash(msg *mail.Message) []byte {
	b := d.canonicalBody(msg)
	digest := d.conf.Hash().New()
	digest.Write([]byte(b))

	return digest.Sum(nil)
}

func (d *DKIM) signableHeaderBlock(msg *mail.Message) string {
	signableHeaderList := make(mail.Header)
	signableHeaderKeys := make([]string, 0)

	for _, k := range d.signableHeaders {
		if v := msg.Header[k]; len(v) != 0 {
			signableHeaderList[k] = v
			signableHeaderKeys = append(signableHeaderKeys, k)
		}
	}

	d.conf[BodyHashKey] = base64.StdEncoding.EncodeToString(d.canonicalBodyHash(msg))
	d.conf[FieldsKey] = strings.Join(signableHeaderKeys, ":")

	signableHeaderList[SignatureHeaderKey] = []string{d.conf.String()}
	signableHeaderKeys = append(signableHeaderKeys, SignatureHeaderKey)

	relax := d.conf.RelaxedHeader()
	canonical := make([]string, 0, len(signableHeaderKeys))
	for _, k := range signableHeaderKeys {
		v := signableHeaderList[k][0]
		if relax {
			v = headerRelaxRx.ReplaceAllString(v, " ")
			k = strings.ToLower(k)
		}
		canonical = append(canonical, k+":"+strings.TrimSpace(v))
	}
	// According to RFC6376 http://tools.ietf.org/html/rfc6376#section-3.7
	// the DKIM header must be inserted without a trailing <CRLF>.
	// That's why we have to trim the space from the canonical header.
	return strings.TrimSpace(strings.Join(canonical, "\r\n") + "\r\n")
}

func (d *DKIM) signature(msg *mail.Message) (string, error) {
	block := d.signableHeaderBlock(msg)
	hash := d.conf.Hash()
	digest := hash.New()
	digest.Write([]byte(block))

	sig, err := rsa.SignPKCS1v15(rand.Reader, d.privateKey, hash, digest.Sum(nil))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

func (d *DKIM) Sign(eml []byte) (signed []byte, err error) {
	msg, err := readEML(eml)

	body := new(bytes.Buffer)
	body.ReadFrom(msg.Body)
	bodyb := body.Bytes()

	// Replace the Reader
	msg.Body = body

	if err != nil {
		return
	}
	sig, err := d.signature(msg)
	if err != nil {
		return
	}
	d.conf[SignatureDataKey] = sig

	// Append the signature header. Keep in mind these are raw values,
	// so we add a <SP> character before the key-value list
	/* msg.Header[SignatureHeaderKey] = []string{d.conf.String()} */

	buf := new(bytes.Buffer)
	for k, _ := range msg.Header {
		s := k + ": " + msg.Header.Get(k) + "\r\n"
		buf.Write([]byte(s))
	}

	buf.Write([]byte(SignatureHeaderKey + ":" + d.conf.String()))
	buf.Write([]byte("\r\n\r\n"))
	buf.Write(bodyb)

	signed = buf.Bytes()

	return
}
