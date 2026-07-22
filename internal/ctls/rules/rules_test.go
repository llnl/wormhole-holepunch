package rules

import (
	"net/url"
	"testing"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/stretchr/testify/assert"
)

type ruleTest struct {
	val     any
	wantErr bool
}

func runRuleTest(t *testing.T, tag string, tests map[string]ruleTest) {
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			v := NewValidator()
			err := v.Var(tt.val, tag)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func makeIllegalStringLength() string {
	b := make([]byte, maxHeaderKB+1)
	for i := range b {
		b[i] = "a"[0]
	}
	return string(b)
}

//

func Test_checkReqToken(t *testing.T) {
	runRuleTest(t, "reqToken", map[string]ruleTest{
		"empty":                              {val: "", wantErr: false},
		"alphanumeric + underscore + hyphen": {val: "EArXoCj8g_miAa8e-ZzP_iR", wantErr: true},
		"period starting":                    {val: ".EArXoCj8g_miAa8e-ZzP_iR", wantErr: true},
		"illegal character":                  {val: "test$(%)string", wantErr: true},
		"invalid length":                     {val: makeIllegalStringLength(), wantErr: true},
		"random jwt": {
			val:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantErr: true,
		},
		"tilde used": {val: "token~123456", wantErr: true},
		"valid":      {val: "109ff5d7-dae0-48c8-8fad-4341c2595829.token", wantErr: false},
		"integer":    {val: 123, wantErr: true},
		"base64":     {val: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=", wantErr: true},
	})
}

func Test_checkKID(t *testing.T) {
	runRuleTest(t, "kid", map[string]ruleTest{
		"invalid characters":                              {val: "group/$(project)/1", wantErr: true},
		"valid kid (gitlab.com/oauth/discovery/keys - 0)": {val: "kewiQq9jiC84CvSsJYOB-N6A8WFLSV20Mb-y7IlWDSQ", wantErr: false},
		"valid kid (gitlab.com/oauth/discovery/keys - 1)": {val: "4i3sFE7sxqNPOT7FdvcGA1ZVGGI_r-tsDXnEuYT4ZqE", wantErr: false},
		"single number":                                   {val: "1", wantErr: false},
		"integer":                                         {val: 123, wantErr: true},
		"invalid length":                                  {val: makeIllegalStringLength(), wantErr: true},
	})
}

func Test_checkWormholeURL(t *testing.T) {
	runRuleTest(t, "wormholeURL", map[string]ruleTest{
		"empty":       {val: "", wantErr: false},
		"path url":    {val: "https://foo.example.com/path", wantErr: false},
		"example url": {val: "https://foo.example.com", wantErr: false},
		"k8s service": {val: "http://static.namespace.svc.cluster.local", wantErr: false},
		"URLString": {val: keys.URLString{
			URL: &url.URL{Scheme: "http", Host: "example.com"}, Raw: "https://example.com",
		}, wantErr: false},
		"integer":        {val: 123, wantErr: true},
		"invalid length": {val: makeIllegalStringLength(), wantErr: true},
	})
}

func Test_headerVal(t *testing.T) {
	runRuleTest(t, "headerVal", map[string]ruleTest{
		"empty":          {val: "", wantErr: false},
		"username":       {val: "user", wantErr: false},
		"usernames":      {val: []string{"foo", "bar"}, wantErr: false},
		"NUL":            {val: "ok\x00bad", wantErr: true},
		"integer":        {val: 123, wantErr: true},
		"invalid length": {val: makeIllegalStringLength(), wantErr: true},
	})
}
