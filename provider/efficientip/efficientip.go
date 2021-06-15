package efficientip

import (
	eip "EIPClient"
	"context"
	"crypto/tls"
	"net/http"
	"strconv"

	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

type EfficientIPConfig struct {
	DomainFilter endpoint.DomainFilter
	ZoneIDFilter provider.ZoneIDFilter
	DryRun       bool
	Host         string
	Port         int
	Username     string
	Password     string
	SSlVerify    bool
}

type EfficientIPProvider struct {
	provider.BaseProvider
	domainFilter endpoint.DomainFilter
	zoneIDFilter provider.ZoneIDFilter
	dryRun       bool
	client       *eip.APIClient
	context      context.Context
}

func NewEfficientIPProvider(config EfficientIPConfig) (*EfficientIPProvider, error) {
	clientConfig := eip.NewConfiguration()
	if !config.SSlVerify {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		clientConfig.HTTPClient = &http.Client{Transport: customTransport}
	}

	client := eip.NewAPIClient(clientConfig)
	ctx := context.WithValue(context.Background(), eip.ContextBasicAuth, eip.BasicAuth{
		UserName: config.Username,
		Password: config.Password,
	})
	ctx = context.WithValue(ctx, eip.ContextServerVariables, map[string]string{
		"your_solidserver_fqdn": config.Host,
		"port":                  strconv.Itoa(config.Port),
	})

	eipProvider := &EfficientIPProvider{
		domainFilter: config.DomainFilter,
		zoneIDFilter: config.ZoneIDFilter,
		dryRun:       config.DryRun,
		client:       client,
		context:      ctx,
	}
	return eipProvider, nil
}

type ZoneAuth struct {
	Name string
	Type string
	Id   string
}

func (p *EfficientIPProvider) NewZoneAuth(zone eip.DnsZoneDataData) *ZoneAuth {
	return &ZoneAuth{
		Name: zone.GetZoneName(),
		Type: zone.GetZoneType(),
		Id:   zone.GetZoneId(),
	}
}

func (p *EfficientIPProvider) Zones(ctx context.Context) ([]*ZoneAuth, error) {
	var result []*ZoneAuth

	zones, _, err := p.client.DnsApi.DnsZoneList(p.context).Execute()

	if err.Error() != "" {
		return nil, err
	}

	for _, zone := range *zones.Data {
		if !p.domainFilter.Match(zone.GetZoneName()) {
			log.Debugf("Ignore zone [%s] by domainFilter", zone.GetZoneName())
			continue
		}
		if p.zoneIDFilter.Match(zone.GetZoneId()) {
			log.Debugf("Ignore zone [%s][%s] by zoneIDFilter", zone.GetZoneName(), zone.GetZoneId())
			continue
		}
		result = append(result, p.NewZoneAuth(zone))
	}
	return result, nil
}

// Records gets the current records.
func (p *EfficientIPProvider) Records(ctx context.Context) (endpoints []*endpoint.Endpoint, _ error) {
	log.Debug("Using EfficientIP")

	var result []*endpoint.Endpoint

	zones, err := p.Zones(ctx)
	if err != nil {
		return nil, err
	}

	for _, zone := range zones {
		records, _, err := p.client.DnsApi.DnsRrList(p.context).Where("dnszone_id=" + zone.Id).Execute()
		if err.Error() != "" {
			log.Errorf("Failed to get RRs for zone [%s]", zone.Name)
			return nil, err
		}

		for _, rr := range *records.Data {

			switch rr.GetRrType() {
			case "A":
			case "TXT":
			case "CNAME":
			default:
			}
		}
	}
	//endpoints = append(endpoints, endpoint.NewEndpoint(res.Name, endpoint.RecordTypeA, ip.Ipv4Addr))
	return endpoints, nil
}

// ApplyChanges applies the given changes.
func (p *EfficientIPProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	panic("implement me")

}

func (p *EfficientIPProvider) PropertyValuesEqual(name string, previous string, current string) bool {
	return p.BaseProvider.PropertyValuesEqual(name, previous, current)
}

func (p *EfficientIPProvider) AdjustEndpoints(endpoints []*endpoint.Endpoint) []*endpoint.Endpoint {
	return endpoints
}
