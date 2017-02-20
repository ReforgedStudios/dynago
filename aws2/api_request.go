package aws2

import (
	"errors"
	"strings"
	"github.com/valyala/fasthttp"
	"net/url"
	"net/http"
)

// DynamoTargetPrefix is the Dynamo API version we support.
const DynamoTargetPrefix = "DynamoDB_20120810."

// MaxResponseSize is the maximum size of a response.
var MaxResponseSize int64 = 25 * 1024 * 1024 // 25MB maximum response

// ErrMaxResponse is returned when responses are too big.
var ErrMaxResponse = errors.New("Exceeded maximum response size of 25MB")

// A Signer's job is to perform API signing.
type Signer interface {
	SignRequest(*fasthttp.Request, []byte)
}

/*
RequestMaker is the default AwsRequester used by Dynago.

The RequestMaker has its properties exposed as public to allow easier
construction. Directly modifying properties on the RequestMaker after
construction is not goroutine-safe so it should be avoided except for in
special cases (testing, mocking).
*/
type RequestMaker struct {
	// These are required to be set
	Endpoint   string
	Signer     Signer
	BuildError func(*http.Request, []byte, *http.Response, []byte) error

	// These can be optionally set
	Caller         *fasthttp.Client
	DebugRequests  bool
	DebugResponses bool
	DebugFunc      func(string, ...interface{})
}

/*
2017/02/20 22:07:41 Dynago DEBUG: Request:&{
POST https://dynamodb.us-east-1.amazonaws.com:443/ HTTP/1.1 %!s(int=1) %!s(int=1)
map[
Authorization:[
AWS4-HMAC-SHA256
 Credential=AKIAIVMZCJXQVO45IGUQ/20170220/us-east-1/dynamodb/aws4_request,
 SignedHeaders=content-type;host;x-amz-date;x-amz-target,
 Signature=08bca6698d10473a517307e7fd052c6b13acf0b0e4d9e8451b640a665a97f75a]
 X-Amz-Target:[DynamoDB_20120810.DescribeTable]
 Content-Type:[application/x-amz-json-1.0]
 Host:[dynamodb.us-east-1.amazonaws.com:443]
 X-Amz-Date:[20170220T200741Z]]
 {{"TableName":"armies"}} %!s(int64=22) [] %!s(bool=false) dynamodb.us-east-1.amazonaws.com:443 map[] map[] %!s(*multipart.Form=<nil>) map[]   %!s(*tls.ConnectionState=<nil>) %!s(<-chan struct {}=<nil>) %!s(*http.Response=<nil>) <nil>} "https://dynamodb.us-east-1.amazonaws.com:443/"
*/
/*
Request:https://dynamodb.us-east-1.amazonaws.com:443/
POST https://dynamodb.us-east-1.amazonaws.com:443/ HTTP/1.1
User-Agent: fasthttp
Host: dynamodb.us-east-1.amazonaws.com:443
Content-Type: application/x-www-form-urlencoded
X-Amz-Target: DynamoDB_20120810.DescribeTable
Content-Type: application/x-amz-json-1.0
X-Amz-Date: 20170220T200743Z
Authorization:
AWS4-HMAC-SHA256
Credential=AKIAIVMZCJXQVO45IGUQ/20170220/us-east-1/dynamodb/aws4_request,
SignedHeaders=content-type;host;x-amz-date;x-amz-target,
Signature=7c94297e92ef86c7c56878741e4dca87a091547aacb50e4021c07479cd4bcd61
*/

func (r *RequestMaker) MakeRequest(target string, body []byte) ([]byte, error) {
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
	req.SetBody(body)
	r.Signer.SignRequest(req, body)
	if r.DebugRequests {
		r.DebugFunc("Request:%s %s\n\nRequest Body: %s\n\n", req.URI().String(), req.Header.String(), body)
	}
	err := r.Caller.Do(req, resp)
	if err != nil {
		return nil, err
	}
	respBody := resp.Body()
	if r.DebugResponses {
		r.DebugFunc("Response: %#v\nBody:%s\n", resp, respBody)
	}
	if resp.StatusCode() != http.StatusOK {
		err = r.BuildError(nil, body, nil, respBody)
	}
	return respBody, err
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
