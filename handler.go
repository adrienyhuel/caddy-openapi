package openapi

import (
	"fmt"
	"strings"

	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func (oapi OpenAPI) ServeHTTP(w http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {

	var direction string

	server := req.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	shouldLogCredentials := server.Logs != nil && server.Logs.ShouldLogCredentials

	loggableReq := zap.Object("request", caddyhttp.LoggableHTTPRequest{
		Request:              req,
		ShouldLogCredentials: shouldLogCredentials,
	})

	errLogger := oapi.logger.WithLazy(loggableReq, zap.String("direction", direction), zap.Bool("fall_through", oapi.FallThrough))

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

	direction = "input"

	route, pathParams, err := oapi.router.FindRoute(req)

	if nil != err {
		replacer.Set(OPENAPI_ERROR, err.Error())
		replacer.Set(OPENAPI_STATUS_CODE, 404)
		if oapi.LogError {
			errLogger.Error("Path not found in OpenAPI", zap.Error(err))
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
					errLogger.Error("Error during OpenAPI request validation", zap.Error(err))
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
				errLogger.Error("Error during evaluation policy", zap.Error(err))
			}
			return nil
		}

		if !result {
			err = fmt.Errorf("Denied: %s", query)
			replacer.Set(OPENAPI_ERROR, err.Error())
			replacer.Set(OPENAPI_STATUS_CODE, 403)
			if oapi.LogError {
				errLogger.Error("Policy error", zap.Error(err))
			}
			return err
		}
	}

	wrapper := &WrapperResponseWriter{ResponseWriter: w}
	if err := next.ServeHTTP(wrapper, req); nil != err {
		return err
	}

	direction = "output"

	if nil != oapi.contentMap {
		contentType := w.Header().Get("Content-Type")
		if "" == contentType {
			return nil
		}
		contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
		_, ok := oapi.contentMap[contentType]
		if !ok {
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

		if (nil != wrapper.Buffer) && (len(wrapper.Buffer) > 0) {
			validateRespInput := &openapi3filter.ResponseValidationInput{
				RequestValidationInput: validateReqInput,
				Status:                 wrapper.StatusCode,
				Header:                 http.Header{"Content-Type": oapi.Check.ResponseBody},
			}
			validateRespInput.SetBodyBytes(wrapper.Buffer)
			if err := openapi3filter.ValidateResponse(req.Context(), validateRespInput); nil != err {
				respErr := err.(*openapi3filter.ResponseError)
				replacer.Set(OPENAPI_RESPONSE_ERROR, respErr.Error())
				errLogger.Error("Error during OpenAPI response validation", zap.Error(respErr))
			}
		}
	}
	return nil
}
