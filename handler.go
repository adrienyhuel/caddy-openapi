package openapi

import (
	"bytes"
	"fmt"
	"strings"

	"net/http"

	"sync"

	"github.com/getkin/kin-openapi/openapi3filter"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func (oapi OpenAPI) ServeHTTP(w http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {

	url := req.URL
	if oapi.ValidateServers {
		url.Host = req.Host
		if nil == req.TLS {
			url.Scheme = "http"
		} else {
			url.Scheme = "https"
		}
	}

	replacer := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	replacer.Set(OPENAPI_ERROR, "")
	replacer.Set(OPENAPI_STATUS_CODE, "")
	replacer.Set(OPENAPI_RESPONSE_ERROR, "")

	route, pathParams, err := oapi.router.FindRoute(req)

	if nil != err {
		replacer.Set(OPENAPI_ERROR, err.Error())
		replacer.Set(OPENAPI_STATUS_CODE, 404)
		if oapi.LogError {
			oapi.err(fmt.Sprintf("%s %s %s: %s", getIP(req), req.Method, req.RequestURI, err))
		}
		if !oapi.FallThrough {
			return err
		}
	}

	// don't check if we have a 404 on the route
	if (nil == err) && (nil != oapi.Check) {
		if oapi.Check.RequestParams {
			validateReqInput := &openapi3filter.RequestValidationInput{
				Request:    req,
				PathParams: pathParams,
				Route:      route,
				Options: &openapi3filter.Options{
					ExcludeRequestBody: !oapi.Check.RequestBody,
				},
			}
			err = openapi3filter.ValidateRequest(req.Context(), validateReqInput)
			if err != nil {
				if reqErr, ok := err.(*openapi3filter.RequestError); ok {
					// Handle request validation error
					replacer.Set(OPENAPI_ERROR, reqErr.Error())
					replacer.Set(OPENAPI_STATUS_CODE, 400)

				} else {
					// Handle security requirements validation error
					securityReqErr := err.(*openapi3filter.SecurityRequirementsError)
					replacer.Set(OPENAPI_ERROR, securityReqErr.Error())
					replacer.Set(OPENAPI_STATUS_CODE, 500)
				}

				if oapi.LogError {
					oapi.err(fmt.Sprintf(">> %s %s %s: %s", getIP(req), req.Method, req.RequestURI, err))
				}
				if !oapi.FallThrough {
					return err
				}
			}
		}
	}

	if query, exists := resolvePolicy(route, req.Method); exists {
		result, err := evalPolicy(query, oapi.policy, req, pathParams)
		if nil != err {
			replacer.Set(OPENAPI_ERROR, err.Error())
			replacer.Set(OPENAPI_STATUS_CODE, 403)
			if oapi.LogError {
				oapi.err(err.Error())
			}
			return nil
		}

		if !result {
			err = fmt.Errorf("Denied: %s", query)
			replacer.Set(OPENAPI_ERROR, err.Error())
			replacer.Set(OPENAPI_STATUS_CODE, 403)
			if oapi.LogError {
				oapi.err(err.Error())
			}
			return err
		}
	}

	// In case we shouldn't validate responses, we're going to execute the next handler and return early (less overhead)
	if (nil == route) || (nil == oapi.Check) || (nil == oapi.contentMap) {
		return next.ServeHTTP(w, req)
	}

	// get a buffer to hold the response body
	respBuf := bufPool.Get().(*bytes.Buffer)
	respBuf.Reset()
	defer bufPool.Put(respBuf)

	shouldBuffer := func(status int, header http.Header) bool {
		return true
	}
	rec := caddyhttp.NewResponseRecorder(w, respBuf, shouldBuffer)
	if err := next.ServeHTTP(rec, req); nil != err {
		return err
	}

	// if ResponseRecorder was not buffered, we don't need to validate response
	if !rec.Buffered() {
		return nil
	}

	contentType := w.Header().Get("Content-Type")
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))

	_, ok := oapi.contentMap[contentType]
	if ok {
		validateReqInput := &openapi3filter.RequestValidationInput{
			Request:    req,
			PathParams: pathParams,
			Route:      route,
			Options: &openapi3filter.Options{
				ExcludeRequestBody:    true,
				ExcludeResponseBody:   false,
				IncludeResponseStatus: true,
			},
		}

		body := rec.Buffer().Bytes()

		if (nil != body) && (len(body) > 0) {
			validateRespInput := &openapi3filter.ResponseValidationInput{
				RequestValidationInput: validateReqInput,
				Status:                 rec.Status(),
				Header:                 rec.Header(),
			}
			validateRespInput.SetBodyBytes(body)
			if err := openapi3filter.ValidateResponse(req.Context(), validateRespInput); nil != err {
				respErr := err.(*openapi3filter.ResponseError)
				replacer.Set(OPENAPI_RESPONSE_ERROR, respErr.Error())
				if oapi.LogError {
					oapi.err(fmt.Sprintf("<< %s %s %s: %s", getIP(req), req.Method, req.RequestURI, respErr.Error()))
				}
				if !oapi.FallThrough {
					return err
				}
			}
		}
	}

	rec.WriteResponse()

	return nil
}

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}
