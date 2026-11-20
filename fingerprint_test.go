package main

import (
	"net/http"
	"reflect"
	"testing"
)

func TestFingerprintResponseTechnologyRules(t *testing.T) {
	tests := []struct {
		name string
		resp *http.Response
		body string
		want []string
	}{
		{"wordpress body", &http.Response{Header: http.Header{}}, `<link href="/wp-content/themes/site.css">`, []string{"WordPress"}},
		{"wordpress cookie", &http.Response{Header: http.Header{"Set-Cookie": {"wordpress_logged_in_hash=abc; Path=/"}}}, "", []string{"WordPress"}},
		{"laravel cookie", &http.Response{Header: http.Header{"Set-Cookie": {"laravel_session=abc; Path=/"}}}, "", []string{"Laravel"}},
		{"next body", &http.Response{Header: http.Header{}}, `<script id="__NEXT_DATA__">{}</script>`, []string{"Next.js"}},
		{"php header", &http.Response{Header: http.Header{"X-Powered-By": {"PHP/8.3"}}}, "", []string{"PHP"}},
		{"php cookie", &http.Response{Header: http.Header{"Set-Cookie": {"PHPSESSID=abc; Path=/"}}}, "", []string{"PHP"}},
		{"express header", &http.Response{Header: http.Header{"X-Powered-By": {"Express"}}}, "", []string{"Express"}},
		{"express cookie", &http.Response{Header: http.Header{"Set-Cookie": {"connect.sid=abc; Path=/"}}}, "", []string{"Express"}},
		{"asp net header", &http.Response{Header: http.Header{"X-AspNet-Version": {"4.0"}}}, "", []string{"ASP.NET"}},
		{"asp net cookie", &http.Response{Header: http.Header{"Set-Cookie": {"ASP.NET_SessionId=abc; Path=/"}}}, "", []string{"ASP.NET"}},
		{"no evidence", &http.Response{Header: http.Header{"Server": {"Apache"}}}, "<html>ordinary page</html>", []string{"Apache"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _ := fingerprintResponse(tt.resp, []byte(tt.body))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("technologies = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFingerprintResponseEdgeRulesAndDeduplication(t *testing.T) {
	tests := []struct {
		name string
		resp *http.Response
		want []string
	}{
		{"cloudflare ray and cookie", &http.Response{Header: http.Header{"Cf-Ray": {"abc"}, "Set-Cookie": {"__cf_bm=abc; Path=/"}}}, []string{"Cloudflare"}},
		{"cloudfront", &http.Response{Header: http.Header{"Via": {"1.1 abc.cloudfront.net (CloudFront)"}}}, []string{"AWS CloudFront"}},
		{"aws waf action", &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{"X-Amzn-Waf-Action": {"BLOCK"}}}, []string{"AWS WAF"}},
		{"aws waf request id blocked response", &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"X-Amzn-RequestId": {"abc"}}}, []string{"AWS WAF"}},
		{"akamai", &http.Response{Header: http.Header{"Akamai-GRN": {"0.abc"}}}, []string{"Akamai"}},
		{"independent providers", &http.Response{Header: http.Header{"Cf-Ray": {"abc"}, "X-Amz-Cf-Id": {"abc"}, "Akamai-GRN": {"abc"}, "X-Amzn-Waf-Action": {"BLOCK"}}}, []string{"Cloudflare", "AWS CloudFront", "AWS WAF", "Akamai"}},
		{"request id without blocking status", &http.Response{StatusCode: http.StatusOK, Header: http.Header{"X-Amzn-RequestId": {"abc"}}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got, _ := fingerprintResponse(tt.resp, nil)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("edge = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFingerprintResponseBoundsSampleAndHandlesNil(t *testing.T) {
	if tech, edge, _ := fingerprintResponse(nil, []byte(`/wp-content/`)); tech != nil || edge != nil {
		t.Fatalf("nil response yielded %v, %v", tech, edge)
	}
	resp := &http.Response{Header: http.Header{}}
	body := append(make([]byte, 64*1024), []byte(`/wp-content/`)...)
	tech, _, _ := fingerprintResponse(resp, body)
	if len(tech) != 0 {
		t.Fatalf("fingerprint used content beyond sample limit: %v", tech)
	}
}
