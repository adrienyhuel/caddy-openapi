package openapi

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/open-policy-agent/opa/rego"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

const (
	MODULE_ID              = "http.handlers.openapi"
	X_POLICY               = "x-policy"
	OPENAPI_ERROR          = "openapi.error"
	OPENAPI_STATUS_CODE    = "openapi.status_code"
	TOKEN_OPENAPI          = "openapi"
	TOKEN_POLICY_BUNDLE    = "policy_bundle"
	TOKEN_SPEC             = "spec"
	TOKEN_FALL_THROUGH     = "fall_through"
	TOKEN_LOG_ERROR        = "log_error"
	TOKEN_VALIDATE_SERVERS = "validate_servers"
	TOKEN_CHECK            = "check"
	TOKEN_SKIP_MISSING_SPEC= "skip_missing_spec"
	TOKEN_ADD_SERVERS      = "additional_servers"
	TOKEN_REPLACE_SERVERS  = "replace_servers"
	TOKEN_ERROR_RESPONSE   = "error_response"
	VALUE_REQ_PARAMS       = "req_params"
	VALUE_REQ_BODY         = "req_body"
	VALUE_RESP_BODY        = "resp_body"
)

// This middleware validates request against an OpenAPI V3 specification. No conforming request can be rejected
type OpenAPI struct {
	// The location of the OASv3 file
	Spec string `json:"spec"`

	PolicyBundle string `json:"policy_bundle"`

	// Should the request proceed if it fails validation. Default is `false`
	FallThrough bool `json:"fall_through,omitempty"`

	// Should the non compliant request be logged? Default is `false`
	LogError bool `json:"log_error,omitempty"`

	// Enable request and response validation
	Check *CheckOptions `json:"check,omitempty"`

	// Enable server validation
	ValidateServers bool `json:"valid_servers,omitempty"`

	// Should the request proceed if spec is missing. Default is `false`
	SkipMissingSpec bool `json:"skip_missing_spec,omitempty"`

	// A list of additional servers to be considered valid when
	// when performing the request validation. The additional servers
	// are added to the servers in the OpenAPI specification.
	// Default is empty list
	AdditionalServers []string `json:"additional_servers,omitempty"`

	// Make AdditionalServers replace existing servers in spec
	ReplaceServers bool `json:"replace_servers,omitempty"`

	// Error response format
	ErrorResponse *ErrorResponse `json:"error_response,omitempty"`

	oas    *openapi3.T
	router routers.Router

	logger *zap.Logger

	policy func(*rego.Rego)
}

type CheckOptions struct {
	// Enable request query validation. Default is `false`
	RequestParams bool `json:"req_params,omitempty"`

	// Enable request payload validation. Default is `false`
	RequestBody bool `json:"req_body,omitempty"`

	// Enable response body validation with an optional list of
	// `Content-Type` to examine. Default `application/json`. If you set
	// your content type, the default will be removed
	ResponseBody []string `json:"resp_body"`
}

type ErrorResponse struct {
	Template string `json:"template,omitempty"`
	Code string `json:"code,omitempty"`
}

var (
	_ caddy.Provisioner           = (*OpenAPI)(nil)
	_ caddy.Validator             = (*OpenAPI)(nil)
	_ caddyfile.Unmarshaler       = (*OpenAPI)(nil)
	_ caddyhttp.MiddlewareHandler = (*OpenAPI)(nil)
)

func init() {
	caddy.RegisterModule(OpenAPI{})
	httpcaddyfile.RegisterHandlerDirective(TOKEN_OPENAPI, parseCaddyFile)
}

func (oapi OpenAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  MODULE_ID,
		New: func() caddy.Module { return new(OpenAPI) },
	}
}

func (oapi *OpenAPI) Provision(ctx caddy.Context) error {

	var oas *openapi3.T
	var err error

	oapi.logger = ctx.Logger(oapi)
	defer oapi.logger.Sync()

	if nil == oapi.ErrorResponse {
		oapi.ErrorResponse = new(ErrorResponse)
	}

	if oapi.ErrorResponse.Code == "" {
		oapi.ErrorResponse.Code = "400"
	}

	oapi.log(fmt.Sprintf("Using OpenAPI spec: %s", oapi.Spec))

	parse_spec := func() error {
		if strings.HasPrefix("http", oapi.Spec) {
			var u *url.URL
			if u, err = url.Parse(oapi.Spec); nil != err {
				return err
			}
			if oas, err = openapi3.NewLoader().LoadFromURI(u); nil != err {
				return err
			}
		} else if _, err = os.Stat(oapi.Spec); !(nil == err || os.IsExist(err)) {
			return err

		} else if oas, err = openapi3.NewLoader().LoadFromFile(oapi.Spec); nil != err {
			return err
		}

		return nil
	}

	parse_err := parse_spec()

	if nil != parse_err {
		if !oapi.SkipMissingSpec {
			return parse_err
		} else {
			oapi.log("OpenAPI spec missing or malformed, skipping...")
			return nil
		}
	}

	if oapi.ValidateServers {

		if oapi.ReplaceServers && len(oapi.AdditionalServers) != 0 {
			oas.Servers = make([]*openapi3.Server, 0)
		}

		for i, s := range oapi.AdditionalServers {
			server := &openapi3.Server{
				URL:         s,
				Description: fmt.Sprintf("Additional server: %d", i),
				Variables:   make(map[string]*openapi3.ServerVariable),
			}
			oas.Servers = append(oas.Servers, server)
		}

		oapi.log("List of servers")
		for _, s := range oas.Servers {
			oapi.log(fmt.Sprintf("- %s #%s", s.URL, s.Description))
		}
	} else {
		// clear all servers
		oapi.log("Disabling server validation")
		oas.Servers = make([]*openapi3.Server, 0)
	}

	router, err := gorillamux.NewRouter(oas)

	if nil != err {
		return err
	}

	oapi.oas = oas
	oapi.router = router

	if (nil != oapi.Check) && (nil != oapi.Check.ResponseBody) {
		if len(oapi.Check.ResponseBody) <= 0 {
			oapi.Check.ResponseBody = append(oapi.Check.ResponseBody, "application/json")
		}
	}

	if len(oapi.PolicyBundle) > 0 {
		oapi.log(fmt.Sprintf("Loaded policy bundle: %s", oapi.PolicyBundle))
		oapi.policy = rego.LoadBundle(oapi.PolicyBundle)
	}

	return nil
}

func (oapi OpenAPI) Validate() error {
	return nil
}

func (oapi *OpenAPI) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {

	oapi.Spec = ""
	oapi.PolicyBundle = ""
	oapi.FallThrough = false
	oapi.LogError = false
	oapi.ValidateServers = true
	oapi.Check = nil
	oapi.AdditionalServers = make([]string, 0)
	oapi.ReplaceServers = false
	oapi.ErrorResponse = new(ErrorResponse)

	// Skip the openapi directive
	d.Next()
	args := d.RemainingArgs()
	if 1 == len(args) {
		d.NextArg()
		oapi.Spec = d.Val()
	}

	for nest := d.Nesting(); d.NextBlock(nest); {
		token := d.Val()
		switch token {
		case TOKEN_SPEC:
			if !d.NextArg() {
				return d.Err("Missing OpenAPI spec file")
			} else {
				oapi.Spec = d.Val()
			}
			if d.NextArg() {
				return d.ArgErr()
			}

		case TOKEN_POLICY_BUNDLE:
			if !d.NextArg() {
				return d.Err("Missing policy bundle")
			} else {
				oapi.PolicyBundle = d.Val()
			}
			if d.NextArg() {
				return d.ArgErr()
			}

		case TOKEN_VALIDATE_SERVERS:
			if d.NextArg() {
				b, err := strconv.ParseBool(d.Val())
				if nil == err {
					oapi.ValidateServers = b
				}
			}

		case TOKEN_FALL_THROUGH:
			if d.NextArg() {
				return d.ArgErr()
			}
			oapi.FallThrough = true

		case TOKEN_LOG_ERROR:
			if d.NextArg() {
				return d.ArgErr()
			}
			oapi.LogError = true

		case TOKEN_CHECK:
			err := parseCheckDirective(oapi, d)
			if nil != err {
				return err
			}

		case TOKEN_SKIP_MISSING_SPEC:
			if d.NextArg() {
				return d.ArgErr()
			}
			oapi.SkipMissingSpec = true

		case TOKEN_ADD_SERVERS:
			oapi.AdditionalServers = d.RemainingArgs()

		case TOKEN_REPLACE_SERVERS:
			if d.NextArg() {
				b, err := strconv.ParseBool(d.Val())
				if nil == err {
					oapi.ReplaceServers = b
				}
			}

		case TOKEN_ERROR_RESPONSE:
			args := d.RemainingArgs()
			if len(args) == 2 {
				oapi.ErrorResponse.Template = args[0]
				oapi.ErrorResponse.Code = args[1]
			} else {
				return d.ArgErr()
			}

		default:
			return d.Errf("unrecognized subdirective: '%s'", token)
		}
	}

	if "" == oapi.Spec {
		return d.Err("missing OpenAPI spec file")
	}
	return nil
}

func parseCaddyFile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var oapi OpenAPI
	err := oapi.UnmarshalCaddyfile(h.Dispenser)
	return oapi, err
}
