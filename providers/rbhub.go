package providers

import (
	"context"
	"errors"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
 	"github.com/tidwall/gjson"
//	"github.com/davecgh/go-spew/spew"
)

// RBHubProvider represents an RBHub based Identity Provider
type RBHubProvider struct {
	*ProviderData
}

var _ Provider = (*RBHubProvider)(nil)

const (
	rbhubProviderName = "RBHub"
	rbhubDefaultScope = "user.info user.email.read"
)

var (
	// Default Login URL for RBHub.
	rbhubDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "hub.rocketbeans.de",
		Path:   "/beanshub/oauth2/authorize",
	}

	// Default Redeem URL for RBHub.
	rbhubDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "api.hub.rocketbeans.de",
		Path:   "/v1/oauth2/token",
	}

	// Default Profile URL for RBHub.
	rbhubDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "api.hub.rocketbeans.de",
		Path:   "/v1/user/self",
	}
)

// NewRBHubProvider initiates a new RBHubProvider
func NewRBHubProvider(p *ProviderData) *RBHubProvider {
	p.setProviderDefaults(providerDefaults{
		name:        rbhubProviderName,
		loginURL:    rbhubDefaultLoginURL,
		redeemURL:   rbhubDefaultRedeemURL,
		profileURL:  rbhubDefaultProfileURL,
		validateURL: rbhubDefaultProfileURL,
		scope:       rbhubDefaultScope,
	})
	p.getAuthorizationHeaderFunc = makeOIDCHeader
	return &RBHubProvider{ProviderData: p}
}

// GetEmailAddress returns the Account email address
func (p *RBHubProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}


	requestURL := p.ProfileURL.String()
	result := requests.New(requestURL).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		Body()
		
	if result == nil {
		return "", errors.New("request error: " + string(result))
	}

	email := gjson.Get(string(result), "data.email").String()
	if email == "" {
		return "", errors.New("no email")
	}
	
	return email, nil
}

// ValidateSession validates the AccessToken
func (p *RBHubProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
