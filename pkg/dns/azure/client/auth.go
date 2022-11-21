package client

import (
	"context"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/pkg/errors"
)

type workloadIdentityCredential struct {
	assertion, file string
	cred            *azidentity.ClientAssertionCredential
	lastRead        time.Time
}

type workloadIdentityCredentialOptions struct {
	azcore.ClientOptions
}

func newWorkloadIdentityCredential(tenantID, clientID, file string, options *workloadIdentityCredentialOptions) (*workloadIdentityCredential, error) {
	w := &workloadIdentityCredential{file: file}
	cred, err := azidentity.NewClientAssertionCredential(tenantID, clientID, w.getAssertion, &azidentity.ClientAssertionCredentialOptions{ClientOptions: options.ClientOptions})
	if err != nil {
		return nil, err
	}
	w.cred = cred
	return w, nil
}

func (w *workloadIdentityCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return w.cred.GetToken(ctx, opts)
}

func (w *workloadIdentityCredential) getAssertion(context.Context) (string, error) {
	if now := time.Now(); w.lastRead.Add(5 * time.Minute).Before(now) {
		content, err := os.ReadFile(w.file)
		if err != nil {
			return "", err
		}
		w.assertion = string(content)
		w.lastRead = now
	}
	return w.assertion, nil
}

func getTokenCredentialForResource(config Config) (azcore.TokenCredential, error) {
	var (
		cred azcore.TokenCredential
		err  error
	)
	// clientSecret wasn't provided, attempt to create a WorkloadIdentityCredential
	if config.ClientSecret == "" {
		options := workloadIdentityCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Cloud: config.Cloud,
			},
		}
		cred, err = newWorkloadIdentityCredential(config.TenantID,
			config.ClientID,
			"/var/run/secrets/openshift/serviceaccount/token",
			&options)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create workload identity credential")
		}
	} else {
		options := azidentity.ClientSecretCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Cloud: config.Cloud,
			},
		}
		cred, err = azidentity.NewClientSecretCredential(config.TenantID, config.ClientID, config.ClientSecret, &options)
		if err != nil {
			return nil, err
		}
	}
	return cred, nil
}
