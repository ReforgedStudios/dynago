package aws

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"encoding/json"
)

// DynamoTargetPrefix is the Dynamo API version we support.
const DynamoTargetPrefix = "DynamoDB_20120810."

// MaxResponseSize is the maximum size of a response.
var MaxResponseSize int64 = 25 * 1024 * 1024 // 25MB maximum response

// ErrMaxResponse is returned when responses are too big.
var ErrMaxResponse = errors.New("Exceeded maximum response size of 25MB")

// A Signer's job is to perform API signing.
type Signer interface {
	SignRequest(*http.Request, []byte)
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
	Caller         http.Client
	DebugRequests  bool
	DebugResponses bool
	DebugFunc      func(string, ...interface{})
}

func (r *RequestMaker) MakeRequest(target string, reqObj interface{}, respObj interface{}) error {
	body, err := json.Marshal(reqObj)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", r.Endpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	if !strings.Contains(target, ".") {
		target = DynamoTargetPrefix + target
	}
	req.Header.Add("x-amz-target", target)
	req.Header.Add("content-type", "application/x-amz-json-1.0")
	req.Header.Set("Host", req.URL.Host)
	r.Signer.SignRequest(req, body)
	if r.DebugRequests {
		r.DebugFunc("Request:%s %#v\n\nRequest Body: %s\n\n", req, req.URL.String(), body)
	}
	response, err := r.Caller.Do(req)
	if err != nil {
		return err
	}
	respBody, err := responseBytes(response)
	if r.DebugResponses {
		r.DebugFunc("Response: %#v\nBody:%s\n", response, respBody)
	}
	if response.StatusCode != http.StatusOK {
		err = r.BuildError(req, body, response, respBody)
		return err
	}
	if respObj != nil {
		err = json.Unmarshal(respBody, respObj)
		return err
	}
	return nil
}

func responseBytes(response *http.Response) (output []byte, err error) {
	if response.ContentLength != 0 {
		var buffer bytes.Buffer
		reader := io.LimitReader(response.Body, MaxResponseSize)
		if response.ContentLength > 0 {
			buffer.Grow(int(response.ContentLength)) // avoid a ton of allocations
		}
		var n int64
		n, err = io.Copy(&buffer, reader)
		if n >= MaxResponseSize {
			err = ErrMaxResponse
		} else if err == nil {
			output = buffer.Bytes()
			err = response.Body.Close()
		}
	}
	return
}
