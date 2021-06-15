package efficientip

import (
	"context"
	"crypto/tls"
	"net/http"
	"strconv"

	log "github.com/sirupsen/logrus"
	eip "sdsclient"

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

func (p *EfficientIPProvider) Zones(_ context.Context) ([]*ZoneAuth, error) {
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
	log.Debug("Get Record list from EfficientIP SOLIDserver")

	var result []*endpoint.Endpoint

	zones, err := p.Zones(ctx)
	if err != nil {
		log.Errorf("Failed to get Zone list from EfficientIP SOLIDserver")
		return nil, err
	}

	for _, zone := range zones {
		records, _, err := p.client.DnsApi.DnsRrList(p.context).Where("dnszone_id=" + zone.Id).Execute()
		if err.Error() != "" {
			log.Errorf("Failed to get RRs for zone [%s]", zone.Name)
			return nil, err
		}

		Host := make(map[string]*endpoint.Endpoint)
		for _, rr := range *records.Data {
			switch rr.GetRrType() {
			case "A":
				if h, found := Host[rr.GetRrFullName()+":"+rr.GetRrType()]; found {
					h.Targets = append(h.Targets, rr.GetRrValueAddressAddr())
				} else {
					Host[rr.GetRrFullName()+":"+rr.GetRrType()] = endpoint.NewEndpoint(rr.GetRrFullName(), rr.GetRrType(), rr.GetRrValueAddressAddr())
				}
			case "TXT":
			case "CNAME":
			default:
				endpoints = append(result, endpoint.NewEndpoint(rr.GetRrFullName(), rr.GetRrType(), rr.GetRrValue1()))
			}
		}
		for _, rr := range Host {
			endpoints = append(result, rr)
		}
	}

	return endpoints, nil
}

func (p *EfficientIPProvider) DeleteChanges(_ context.Context, changes *endpoint.Endpoint) error {
	for _, value := range changes.Targets {
		if p.dryRun {
			log.Infof("Would delete %s record named '%s' to '%s' for Efficientip",
				changes.RecordType,
				changes.DNSName,
				value,
			)
			continue
		}
		_, _, err := p.client.DnsApi.DnsRrDelete(p.context).RrName(changes.DNSName).RrType(changes.RecordType).RrValue1(value).Execute()
		if err.Error() != "" {
			log.Errorf("Deletion of the RR %v %v -> %v : failed!", changes.RecordType, changes.DNSName, value)
		}
	}
	return nil
}

func (p *EfficientIPProvider) CreateChanges(_ context.Context, changes *endpoint.Endpoint) error {
	for _, value := range changes.Targets {
		if p.dryRun {
			log.Infof("Would create %s record named '%s' to '%s' for Efficientip",
				changes.RecordType,
				changes.DNSName,
				value,
			)
			continue
		}
		_, _, err := p.client.DnsApi.DnsRrAdd(p.context).DnsRrAddInput(eip.DnsRrAddInput{
			RrName:   &changes.DNSName,
			RrType:   &changes.RecordType,
			RrValue1: &value,
		}).Execute()

		if err.Error() != "" {
			log.Errorf("Creation of the RR %v %v -> %v : failed!", changes.RecordType, changes.DNSName, value)
		}
	}
	return nil
}

// ApplyChanges applies the given changes.
func (p *EfficientIPProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {

	for _, change := range changes.Delete {
		err := p.DeleteChanges(ctx, change)
		if err != nil {
			return err
		}
	}
	for _, change := range changes.UpdateOld {
		err := p.DeleteChanges(ctx, change)
		if err != nil {
			return err
		}
	}
	for _, change := range changes.UpdateNew {
		err := p.CreateChanges(ctx, change)
		if err != nil {
			return err
		}
	}
	for _, change := range changes.Create {
		err := p.CreateChanges(ctx, change)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *EfficientIPProvider) PropertyValuesEqual(name string, previous string, current string) bool {
	return p.BaseProvider.PropertyValuesEqual(name, previous, current)
}

func (p *EfficientIPProvider) AdjustEndpoints(endpoints []*endpoint.Endpoint) []*endpoint.Endpoint {
	return endpoints
}
