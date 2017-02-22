package dynago

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/valyala/fasthttp"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Create an AWS executor with a specified endpoint and AWS parameters.
func NewAwsFHttpExecutor(endpoint, region, accessKey, secretKey string) Executor {
	signer := &fhttpAwsSigner{
		Region:    region,
		AccessKey: accessKey,
		SecretKey: secretKey,
		Service:   "dynamodb",
	}
	timeout := time.Second * 5
	httpcli := &fasthttp.Client{WriteTimeout: timeout, ReadTimeout: timeout, MaxConnsPerHost: 128, MaxIdleConnDuration: time.Second * 30}
	executor := &AwsFHttpExecutor{
		Endpoint:       FixEndpointUrl(endpoint),
		Signer:         signer,
		BuildError:     buildError,
		DebugRequests:  Debug.HasFlag(DebugRequests),
		DebugResponses: Debug.HasFlag(DebugResponses),
		DebugFunc:      DebugFunc,
		httpcli:        httpcli,
	}
	return executor
}

var _ Executor = &AwsFHttpExecutor{}

type AwsFHttpExecutor struct {
	AwsExecutor
	// These are required to be set
	Endpoint   string
	Signer     *fhttpAwsSigner
	BuildError func(*http.Request, []byte, *http.Response, []byte) error

	// These can be optionally set
	httpcli        *fasthttp.Client
	DebugRequests  bool
	DebugResponses bool
	DebugFunc      func(string, ...interface{})
}

const DynamoTargetPrefix = "DynamoDB_20120810."

func (r *AwsFHttpExecutor) MakeRequestUnMarshal(target string, reqObj interface{}, respObj interface{}) error {
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
	err = r.httpcli.Do(req, resp)
	if err != nil {
		return err
	}
	if r.DebugResponses {
		r.DebugFunc("Response: %#v\nBody:%s\n", resp, resp.Body())
	}
	if resp.StatusCode() != http.StatusOK {
		err = r.BuildError(nil, reqBody, nil, resp.Body())
	}
	err = json.Unmarshal(resp.Body(), respObj)
	return err
}

func FixEndpointUrl(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		panic(err)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if u.Scheme == "https" && !strings.Contains(u.Host, ":") {
		u.Host += ":443"
	}
	return u.String()
}

const algorithm = "AWS4-HMAC-SHA256"

/*
AwsSigner signs requests with the AWS v4 request signing algorithm.

This is required for all aws requests to ensure:

	1. request bodies and headers are not tampered with in flight.
	2. It also prevents replay attacks
	3. It also handles authentication without sending or revealing the shared secret
*/
type fhttpAwsSigner struct {
	AccessKey string
	SecretKey string
	Region    string
	Service   string
}

func (info *fhttpAwsSigner) SignRequest(request *fasthttp.Request, bodyBytes []byte) {
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

func signingKey(now time.Time, info *fhttpAwsSigner) []byte {
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
