// Created by Hisen at 2019-06-01.
package bce_auth_golang_sdk

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	url "github.com/hanxinhisen/escape"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	IAM_NOHEADERS        = 400
	IAM_HEADERS_NOHOST   = 401
	IAM_HEADERS_NOSIGNED = 402
	IAM_NOMETHOD         = 420
	IAM_NOURI            = 440
	IAM_SIGNINGKEY       = 460
	IAM_SIGNATURE        = 480
)

type BceSigner struct {
	Access_key string
	Secret_key string
}

type Request struct {
	Method  string
	Uri     string
	Params  Params
	Headers Headers
}

type Headers struct {
	Headers map[string]interface{}
}

type Params struct {
	Params map[string]interface{}
}

func (signer *BceSigner) GenAuthorization(r *Request) (keyStr string) {
	timestamp := ""
	expire_period := 1800
	var signedheaders []string
	for k, _ := range r.Headers.Headers {
		signedheaders = append(signedheaders, strings.ToLower(k))
	}
	sort.Strings(signedheaders)
	authorization := signer.buildAuthorization(signer.Access_key, signedheaders, timestamp, expire_period)
	signingkey := signer.calcSigningkey(authorization)
	signature := signer.calcSignature(signingkey, r, signedheaders)
	authorization["signature"] = signature
	return signer.serialize_authorization(authorization)
}

func (signer *BceSigner) serialize_authorization(auth map[string]interface{}) (authorization string) {
	var authSlice []string
	authSlice = append(authSlice, auth["version"].(string))
	authSlice = append(authSlice, auth["access"].(string))
	authSlice = append(authSlice, auth["timestamp"].(string))
	authSlice = append(authSlice, auth["period"].(string))
	authSlice = append(authSlice, strings.Join(auth["signedheaders"].([]string), ";"))
	authSlice = append(authSlice, auth["signature"].(string))
	return strings.Join(authSlice, "/")
}

func (signer *BceSigner) buildAuthorization(access_key string, signedheaders []string, timestamp string, expire_period int) (auth map[string]interface{}) {
	auth = make(map[string]interface{})
	auth["version"] = "bce-auth-v1"
	auth["access"] = access_key
	if timestamp == "" {
		auth["timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	} else {
		auth["timestamp"] = timestamp
	}

	auth["period"] = strconv.Itoa(expire_period)
	auth["signedheaders"] = signedheaders
	return auth
}

func (signer *BceSigner) calcSigningkey(auth map[string]interface{}) (signingKey string) {
	var tmp []string
	tmp = append(tmp, auth["version"].(string))
	tmp = append(tmp, auth["access"].(string))
	tmp = append(tmp, auth["timestamp"].(string))
	tmp = append(tmp, auth["period"].(string))
	stringToSign := strings.Join(tmp, "/")
	h := hmac.New(sha256.New, []byte(signer.Secret_key))
	h.Write([]byte(stringToSign))
	signingKey = fmt.Sprintf("%x", h.Sum(nil))
	return

}

func (signer *BceSigner) calcSignature(signingkey string, request *Request, signedheaders []string) (signingKey string) {
	if request.Method == "" {
		panic(fmt.Errorf("%d", IAM_NOMETHOD))
	}
	if request.Uri == "" {
		panic(fmt.Errorf("%d", IAM_NOURI))
	}
	params := make(map[string]interface{})
	headers := make(map[string]interface{})

	if len(request.Params.Params) != 0 {
		params = request.Params.Params
	}
	if len(request.Headers.Headers) != 0 {
		headers = request.Headers.Headers
	}

	var crSlice []string
	crSlice = append(crSlice, strings.ToUpper(request.Method))
	crSlice = append(crSlice, signer.normalized_uri(request.Uri))
	crSlice = append(crSlice, signer.canonical_qs(params))
	crSlice = append(crSlice, signer.canonical_header_str(headers, signedheaders))

	cr := strings.Join(crSlice, "\n")
	h := hmac.New(sha256.New, []byte(signingkey))
	h.Write([]byte(cr))
	signingKey = fmt.Sprintf("%x", h.Sum(nil))
	return

}

func (signer *BceSigner) normalized_uri(uri string) (uriR string) {
	return url.PathEscapeWithOutCharacters(uri, "-_.~/")
}
func (signer *BceSigner) normalized(msg string) (msgR string) {
	return url.QueryEscapeWithOutCharacters(msg, "-_.~")
}
func (signer *BceSigner) canonical_qs(p map[string]interface{}) (qs string) {
	keys := []string{}
	for k, _ := range p {
		keys = append(keys, k)
	}
	pairs := []string{}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "authorization" {
			continue
		}
		val := ""
		switch p[k].(type) {
		case string:
			val = signer.normalized(p[k].(string))
		case int:
			valt := strconv.Itoa(p[k].(int))
			val = signer.normalized(valt)
		}

		pairs = append(pairs, url.PathEscape(k)+"="+val)
	}
	return strings.Join(pairs, "&")

}
func (signer *BceSigner) canonical_header_str(h map[string]interface{}, signedheaders []string) (result string) {
	headers_norm_lower := make(map[string]interface{})
	for k, v := range h {
		key_norm_lower := signer.normalized(strings.ToLower(k))
		value_norm_lower := ""
		switch v.(type) {
		case string:
			value_norm_lower = signer.normalized(strings.TrimSpace(v.(string)))
		case int:
			value_norm_lower = signer.normalized(strings.TrimSpace(strconv.Itoa(v.(int))))
		}
		headers_norm_lower[key_norm_lower] = value_norm_lower
	}
	_, ok := headers_norm_lower["host"]
	if !ok {
		panic(fmt.Errorf("%d", IAM_HEADERS_NOHOST))
	}
	var keys []string
	for key, _ := range headers_norm_lower {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var header_list []string
	default_signed := []string{"host", "content-length", "content-type", "content-md5"}
	if len(signedheaders) != 0 {
		for _, k := range signedheaders {
			k = signer.normalized(strings.ToLower(k))
			if !signer.isExist(keys, k) {
				panic(fmt.Errorf("%d", IAM_HEADERS_NOSIGNED))
			}
			v, ok := headers_norm_lower[k]
			if ok {
				header_list = append(header_list, k+":"+v.(string))
			}
		}
	} else {
		for _, k := range keys {
			if strings.HasPrefix(k, "x-bce-") || signer.isExist(default_signed, k) {
				header_list = append(header_list, k+":"+headers_norm_lower[k].(string))
			}
		}
	}
	return strings.Join(header_list, "\n")
}

func (signer *BceSigner) isExist(s []string, item string) bool {
	for _, v := range s {
		if v == item {
			return true
		}
	}
	return false
}
