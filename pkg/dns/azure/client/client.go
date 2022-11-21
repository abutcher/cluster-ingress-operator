package client

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	dns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	privatedns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/pkg/errors"
)

type DNSClient interface {
	Put(ctx context.Context, zone Zone, arec ARecord) error
	Delete(ctx context.Context, zone Zone, arec ARecord) error
}

type Config struct {
	Cloud          cloud.Configuration
	SubscriptionID string
	ClientID       string
	ClientSecret   string
	TenantID       string
}

// ARecord is a DNS A record.
type ARecord struct {
	// Name is the record name.
	Name string

	// Address is the IPv4 address of the A record.
	Address string

	//TTL is the Time To Live property of the A record
	TTL int64

	//Label is the metadata label that needs to be added with the A record.
	Label string
}

type dnsClient struct {
	recordSetClient, privateRecordSetClient DNSClient
}

// New returns an authenticated DNSClient
func New(config Config, userAgentExtension string) (DNSClient, error) {
	rsc, err := newRecordSetClient(config, userAgentExtension)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create recordSetClient")
	}

	prsc, err := newPrivateRecordSetClient(config, userAgentExtension)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create privateRecordSetClient")
	}

	return &dnsClient{recordSetClient: rsc, privateRecordSetClient: prsc}, nil
}

func (c *dnsClient) Put(ctx context.Context, zone Zone, arec ARecord) error {
	switch zone.Provider {
	case "Microsoft.Network/privateDnsZones":
		return c.privateRecordSetClient.Put(ctx, zone, arec)
	case "Microsoft.Network/dnszones":
		return c.recordSetClient.Put(ctx, zone, arec)
	default:
		return errors.Errorf("unsupported Zone provider %s", zone.Provider)
	}
}

func (c *dnsClient) Delete(ctx context.Context, zone Zone, arec ARecord) error {
	switch zone.Provider {
	case "Microsoft.Network/privateDnsZones":
		return c.privateRecordSetClient.Delete(ctx, zone, arec)
	case "Microsoft.Network/dnszones":
		return c.recordSetClient.Delete(ctx, zone, arec)
	default:
		return errors.Errorf("unsupported Zone provider %s", zone.Provider)
	}
}

type recordSetClient struct {
	client dns.RecordSetsClient
}

func newRecordSetClient(config Config, userAgentExtension string) (*recordSetClient, error) {
	cred, err := getTokenCredentialForResource(config)
	if err != nil {
		return nil, err
	}
	options := arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Cloud: config.Cloud,
		},
		DisableRPRegistration: false,
	}
	rc, err := dns.NewRecordSetsClient(config.SubscriptionID, cred, &options)
	if err != nil {
		return nil, err
	}

	return &recordSetClient{client: *rc}, nil
}

func (c *recordSetClient) Put(ctx context.Context, zone Zone, arec ARecord) error {
	rs := dns.RecordSet{
		Properties: &dns.RecordSetProperties{
			TTL: &arec.TTL,
			ARecords: []*dns.ARecord{
				{
					IPv4Address: &arec.Address,
				},
			},
		},
	}
	if arec.Label != "" {
		ownedValue := "owned"
		rs.Properties.Metadata = map[string]*string{arec.Label: &ownedValue}
	}
	_, err := c.client.CreateOrUpdate(ctx, zone.ResourceGroup, zone.Name, arec.Name, dns.RecordTypeA, rs, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to update dns a record: %s.%s", arec.Name, zone.Name)
	}
	return nil
}

func (c *recordSetClient) Delete(ctx context.Context, zone Zone, arec ARecord) error {
	_, err := c.client.Get(ctx, zone.ResourceGroup, zone.Name, arec.Name, dns.RecordTypeA, nil)
	if err != nil {
		// TODO: How do we interpret this as a notfound error?
		return nil
	}
	_, err = c.client.Delete(ctx, zone.ResourceGroup, zone.Name, arec.Name, dns.RecordTypeA, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to delete dns a record: %s.%s", arec.Name, zone.Name)
	}
	return nil
}

type privateRecordSetClient struct {
	client privatedns.RecordSetsClient
}

func newPrivateRecordSetClient(config Config, userAgentExtension string) (*privateRecordSetClient, error) {
	cred, err := getTokenCredentialForResource(config)
	if err != nil {
		return nil, err
	}

	options := arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Cloud: config.Cloud,
		},
		DisableRPRegistration: false,
	}
	prc, err := privatedns.NewRecordSetsClient(config.SubscriptionID, cred, &options)
	if err != nil {
		return nil, err
	}
	return &privateRecordSetClient{client: *prc}, nil
}

func (c *privateRecordSetClient) Put(ctx context.Context, zone Zone, arec ARecord) error {
	rs := privatedns.RecordSet{
		Properties: &privatedns.RecordSetProperties{
			TTL: &arec.TTL,
			ARecords: []*privatedns.ARecord{
				{
					IPv4Address: &arec.Address,
				},
			},
		},
	}
	_, err := c.client.CreateOrUpdate(ctx, zone.ResourceGroup, zone.Name, privatedns.RecordTypeA, arec.Name, rs, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to update dns a record: %s.%s", arec.Name, zone.Name)
	}
	return nil
}

func (c *privateRecordSetClient) Delete(ctx context.Context, zone Zone, arec ARecord) error {
	_, err := c.client.Get(ctx, zone.ResourceGroup, zone.Name, privatedns.RecordTypeA, arec.Name, nil)
	if err != nil {
		// TODO: How do we interpret this as a notfound error?
		return nil
	}
	_, err = c.client.Delete(ctx, zone.ResourceGroup, zone.Name, privatedns.RecordTypeA, arec.Name, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to delete dns a record: %s.%s", arec.Name, zone.Name)
	}
	return nil
}
