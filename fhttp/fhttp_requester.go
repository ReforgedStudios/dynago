package fhttp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/valyala/fasthttp"
	"net/http"
	"sort"
	"strings"
	"time"
)

type FastHttpRequester struct {
	// These are required to be set
	Endpoint   string
	Signer     *FastHttpAwsSigner
	BuildError func(*http.Request, []byte, *http.Response, []byte) error

	// These can be optionally set
	HttpCli        *fasthttp.Client
	DebugRequests  bool
	DebugResponses bool
	DebugFunc      func(string, ...interface{})
	TimeHttp       func(since time.Time)
}

const DynamoTargetPrefix = "DynamoDB_20120810."

func (r *FastHttpRequester) MakeRequest(target string, reqObj interface{}, respObj interface{}) error {
	reqBody, err := json.Marshal(reqObj)
	if err != nil {
		return err
	}
	req := fasthttp.AcquireRequest()
	req.Reset()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod("POST")
	req.SetRequestURI(r.Endpoint)
	if !strings.Contains(target, ".") {
		target = DynamoTargetPrefix + target
	}
	req.Header.Del("User-Agent")
	req.Header.Set("X-Amz-Target", target)
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("Host", string(req.URI().Host()))
	req.SetBody(reqBody)
	r.Signer.SignRequest(req, reqBody)
	if r.DebugRequests {
		r.DebugFunc("Request:%s %s\n\nRequest Body: %s\n\n", req.URI().String(), req.Header.String(), reqBody)
	}

	// retry 3 times
	now := time.Now()
	for i := 0; i < 3 && err != nil; i++ {
		err = r.HttpCli.Do(req, resp)
	}
	r.TimeHttp(now)
	if err != nil {
		return err
	}
	if r.DebugResponses {
		r.DebugFunc("Response: %#v\nBody:%s\n", resp, resp.Body())
	}
	if resp.StatusCode() != http.StatusOK {
		err = r.BuildError(nil, reqBody, nil, resp.Body())
		return err
	}
	if respObj != nil {
		err = json.Unmarshal(resp.Body(), respObj)
		return err
	}
	return nil
}

const algorithm = "AWS4-HMAC-SHA256"

/*
AwsSigner signs requests with the AWS v4 request signing algorithm.

This is required for all aws requests to ensure:

	1. request bodies and headers are not tampered with in flight.
	2. It also prevents replay attacks
	3. It also handles authentication without sending or revealing the shared secret
*/
type FastHttpAwsSigner struct {
	AccessKey string
	SecretKey string
	Region    string
	Service   string
}

func (info *FastHttpAwsSigner) SignRequest(request *fasthttp.Request, bodyBytes []byte) {
	now := time.Now().UTC()
	isoDateSmash := now.Format("20060102T150405Z")
	request.Header.Add("x-amz-date", isoDateSmash)
	canonicalHash, signedHeaders := canonicalRequest(request, bodyBytes)
	credentialScope := now.Format("20060102") + "/" + info.Region + "/" + info.Service + "/aws4_request"
	stringToSign := algorithm + "\n" + isoDateSmash + "\n" + credentialScope + "\n" + canonicalHash
	signingKey := signingKey(now, info)
	signature := hex.EncodeToString(hmacShort(signingKey, []byte(stringToSign)))
	authHeader := algorithm + " Credential=" + info.AccessKey + "/" + credentialScope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	request.Header.Add("Authorization", authHeader)
}

func canonicalRequest(request *fasthttp.Request, bodyBytes []byte) (string, string) {
	var canonical bytes.Buffer
	canonical.Write(request.Header.Method())
	canonical.WriteByte('\n')
	canonical.Write(request.URI().Path())
	canonical.WriteRune('\n')
	canonical.Write(request.URI().QueryString())
	canonical.WriteRune('\n')
	signedHeaders := canonicalHeaders(&canonical, request.Header)
	sum := sha256.Sum256(bodyBytes)
	canonical.WriteString(hex.EncodeToString(sum[:]))
	cBytes := canonical.Bytes()
	sum = sha256.Sum256(cBytes)
	return hex.EncodeToString(sum[:]), signedHeaders
}

func canonicalHeaders(buf *bytes.Buffer, headers fasthttp.RequestHeader) string {
	headerVals := make([]string, 0, headers.Len())
	headerNames := make([]string, 0, headers.Len())
	headers.VisitAll(func(key []byte, val []byte) {
		name := strings.ToLower(string(key))
		s := name + ":" + strings.TrimSpace(string(val))
		headerVals = append(headerVals, s)
		headerNames = append(headerNames, name)
	})
	sort.Strings(headerVals)
	for _, cHeader := range headerVals {
		buf.WriteString(cHeader)
		buf.WriteRune('\n')
	}
	buf.WriteRune('\n')
	sort.Strings(headerNames)
	signedHeaders := strings.Join(headerNames, ";")
	buf.WriteString(signedHeaders)
	buf.WriteRune('\n')
	return signedHeaders
}

func signingKey(now time.Time, info *FastHttpAwsSigner) []byte {
	kSecret := "AWS4" + info.SecretKey
	kDate := hmacShort([]byte(kSecret), []byte(now.Format("20060102")))
	kRegion := hmacShort(kDate, []byte(info.Region))
	kService := hmacShort(kRegion, []byte(info.Service))
	kSigning := hmacShort(kService, []byte("aws4_request"))
	return kSigning
}

func hmacShort(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
