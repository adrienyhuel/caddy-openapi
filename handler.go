package openapi

import (
	"fmt"
	"strings"
	"bytes"
	"slices"

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

	// if oas is nil means that we skipped openapi spec parsing errors and we can't check this request
	if nil == oapi.oas {

		err := fmt.Errorf(">> %s %s %s: %s", getIP(req), req.Method, req.RequestURI, "OpenApi spec is missing or malformed")
		replacer.Set(OPENAPI_ERROR, err.Error())
		replacer.Set(OPENAPI_STATUS_CODE, 403)
		if oapi.LogError {
			oapi.err(err.Error())
		}

		if !oapi.FallThrough {
			return oapi.respond(w, replacer)
		} else {
			return next.ServeHTTP(w, req)
		}
	}

	route, pathParams, err := oapi.router.FindRoute(req)

	if nil != err {
		replacer.Set(OPENAPI_ERROR, err.Error())
		replacer.Set(OPENAPI_STATUS_CODE, 404)
		if oapi.LogError {
			oapi.err(fmt.Sprintf(">> %s %s %s: %s", getIP(req), req.Method, req.RequestURI, err))
		}
		if !oapi.FallThrough {
			return oapi.respond(w, replacer)
		}
	}

	// don't check if we have a 404 on the route
	if (nil != route) && (nil != oapi.Check) {
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
					return oapi.respond(w, replacer)
				}
			}
		}
	}

	// don't check if we have a 404 on the route
	if (nil != route) {
		if query, exists := resolvePolicy(route, req.Method); exists {
			result, err := evalPolicy(query, oapi.policy, req, pathParams)
			if nil != err {
				replacer.Set(OPENAPI_ERROR, err.Error())
				replacer.Set(OPENAPI_STATUS_CODE, 403)
				if oapi.LogError {
					oapi.err(fmt.Sprintf(">> %s %s %s: %s", getIP(req), req.Method, req.RequestURI, err))
				}
				return oapi.respond(w, replacer)
			}

			if !result {
				err = fmt.Errorf("Denied: %s", query)
				replacer.Set(OPENAPI_ERROR, err.Error())
				replacer.Set(OPENAPI_STATUS_CODE, 403)
				if oapi.LogError {
					oapi.err(fmt.Sprintf(">> %s %s %s: %s", getIP(req), req.Method, req.RequestURI, err))
				}
				return oapi.respond(w, replacer)
			}
		}
	}

	// In case we shouldn't validate responses, we're going to execute the next handler and return early (less overhead)
	if (nil == route) || (nil == oapi.Check) || (len(oapi.Check.ResponseBody) <= 0) {
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

	validate_resp := func() error {
		contentType := w.Header().Get("Content-Type")
		if "" == contentType {
			return nil
		}
		contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
		if !slices.Contains(oapi.Check.ResponseBody, contentType) {
			return nil
		}

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
				Header:                 http.Header{"Content-Type": oapi.Check.ResponseBody},
			}
			validateRespInput.SetBodyBytes(body)
			if err := openapi3filter.ValidateResponse(req.Context(), validateRespInput); nil != err {
				respErr := err.(*openapi3filter.ResponseError)
				replacer.Set(OPENAPI_ERROR, respErr.Error())
				replacer.Set(OPENAPI_STATUS_CODE, 400)
				if oapi.LogError {
					oapi.err(fmt.Sprintf("<< %s %s %s: %s", getIP(req), req.Method, req.RequestURI, respErr.Error()))
				}
				if !oapi.FallThrough {
					return err
				}
			}
		}

		return nil
	}

	validate_err := validate_resp()

	if nil != validate_err {
		return oapi.respond(w, replacer)
	}

	rec.WriteResponse()

	return nil
}


var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}