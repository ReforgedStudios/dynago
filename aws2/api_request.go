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

func (r *RequestMaker) MakeRequest(target string, body []byte) ([]byte, error) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod("POST")
	req.SetRequestURI(r.Endpoint)
	req.AppendBody(body)
	if !strings.Contains(target, ".") {
		target = DynamoTargetPrefix + target
	}
	req.Header.Add("x-amz-target", target)
	req.Header.Add("content-type", "application/x-amz-json-1.0")
	req.Header.SetBytesV("Host", req.URI().Host())
	r.Signer.SignRequest(req, body)
	if r.DebugRequests {
		r.DebugFunc("Request:%#v\n\nRequest Body: %s\n\n", req, body)
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
