package consul

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/consul/acl"
	"github.com/hashicorp/consul/agent/agentpb"
	"github.com/hashicorp/consul/agent/agentpb/config"
	"github.com/hashicorp/consul/agent/consul/authmethod/ssoauth"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/lib/template"
	"github.com/hashicorp/consul/tlsutil"
	bexpr "github.com/hashicorp/go-bexpr"
)

type AutoConfigOptions struct {
	NodeName    string
	SegmentName string
}

type AutoConfigAuthorizer interface {
	// Authorizes the request and returns a struct containing the various
	// options for how to generate the configuration.
	Authorize(*agentpb.AutoConfigRequest) (AutoConfigOptions, error)
}

type disabledAuthorizer struct{}

func (_ *disabledAuthorizer) Authorize(_ *agentpb.AutoConfigRequest) (AutoConfigOptions, error) {
	return AutoConfigOptions{}, fmt.Errorf("Auto Config is disabled")
}

type jwtAuthorizer struct {
	validator       *ssoauth.Validator
	allowReuse      bool
	claimAssertions []string
}

func (a *jwtAuthorizer) Authorize(req *agentpb.AutoConfigRequest) (AutoConfigOptions, error) {
	// perform basic JWT Authorization
	identity, err := a.validator.ValidateLogin(context.Background(), req.JWT)
	if err != nil {
		// TODO (autoconf) maybe we should add a more generic permission denied error not tied to the ACL package?
		return AutoConfigOptions{}, acl.PermissionDenied("Failed JWT authorization: %v", err)
	}

	varMap := map[string]string{
		"node":    req.Node,
		"segment": req.Segment,
	}

	for _, raw := range a.claimAssertions {
		// validate and fill any HIL
		filled, err := template.InterpolateHIL(raw, varMap, true)
		if err != nil {
			return AutoConfigOptions{}, fmt.Errorf("Failed to render claim assertion template %q: %w", raw, err)
		}

		evaluator, err := bexpr.CreateEvaluatorForType(filled, nil, identity.SelectableFields)
		if err != nil {
			return AutoConfigOptions{}, fmt.Errorf("Failed to create evaluator for claim assertion %q: %w", filled, err)
		}

		ok, err := evaluator.Evaluate(identity.SelectableFields)
		if err != nil {
			return AutoConfigOptions{}, fmt.Errorf("Failed to execute claim assertion %q: %w", filled, err)
		}

		if !ok {
			return AutoConfigOptions{}, acl.PermissionDenied("Failed JWT claim assertion")
		}
	}

	return AutoConfigOptions{
		NodeName:    req.Node,
		SegmentName: req.Segment,
	}, nil
}

type AutoConfigDelegate interface {
	GetConfig() *Config
	CreateACLToken(template *structs.ACLToken) (*structs.ACLToken, error)
	DatacenterJoinAddresses(segment string) ([]string, error)
	TLSConfigurator() *tlsutil.Configurator
	ForwardRPC(method string, info structs.RPCInfo, args, reply interface{}) (bool, error)
}

// AutoConfig endpoint is used for cluster auto configuration operations
type AutoConfig struct {
	delegate   AutoConfigDelegate
	authorizer AutoConfigAuthorizer
}

// getDelegateConfig is a small wrapper around the delegates GetConfig to ensure
// that all helper functions have a non-nil configuration to operate on.
func (ac *AutoConfig) getDelegateConfig() *Config {
	if conf := ac.delegate.GetConfig(); conf != nil {
		return conf
	}

	return DefaultConfig()
}

// updateTLSCertificatesInConfig will ensure that the TLS settings regarding how an agent is
// made aware of its certificates are populated. This will only work if connect is enabled and
// in some cases only if auto_encrypt is enabled on the servers. This endpoint has the option
// to configure auto_encrypt or potentially in the future to generate the certificates inline.
func (ac *AutoConfig) updateTLSCertificatesInConfig(opts AutoConfigOptions, conf *config.Config) error {
	conf.AutoEncrypt = &config.AutoEncrypt{TLS: ac.getDelegateConfig().AutoEncryptAllowTLS}
	return nil
}

// updateACLtokensInConfig will configure all of the agents ACL settings and will populate
// the configuration with an agent token usable for all default agent operations.
func (ac *AutoConfig) updateACLsInConfig(opts AutoConfigOptions, conf *config.Config) error {
	delegateConf := ac.getDelegateConfig()

	acl := &config.ACL{
		Enabled:             delegateConf.ACLsEnabled,
		PolicyTTL:           delegateConf.ACLPolicyTTL.String(),
		RoleTTL:             delegateConf.ACLRoleTTL.String(),
		TokenTTL:            delegateConf.ACLTokenTTL.String(),
		DisabledTTL:         delegateConf.ACLDisabledTTL.String(),
		DownPolicy:          delegateConf.ACLDownPolicy,
		DefaultPolicy:       delegateConf.ACLDefaultPolicy,
		EnableKeyListPolicy: delegateConf.ACLEnableKeyListPolicy,
	}

	// when ACLs are enabled we want to create a local token with a node identity
	if delegateConf.ACLsEnabled {
		// set up the token template - the ids and create time will be added
		// by the delegate.
		template := structs.ACLToken{
			Description: fmt.Sprintf("Auto Config Token for Node %q", opts.NodeName),
			Local:       true,
			NodeIdentities: []*structs.ACLNodeIdentity{
				{
					NodeName:   opts.NodeName,
					Datacenter: delegateConf.Datacenter,
				},
			},
			EnterpriseMeta: *structs.DefaultEnterpriseMeta(),
		}

		token, err := ac.delegate.CreateACLToken(&template)
		if err != nil {
			return fmt.Errorf("Failed to generate an ACL token for node %q - %w", opts.NodeName, err)
		}

		acl.Tokens = &config.ACLTokens{Agent: token.SecretID}
	}

	conf.ACL = acl
	return nil
}

// updateJoinAddressesInConfig determines the correct gossip endpoints that clients should
// be connecting to for joining the cluster based on the segment given in the opts parameter.
func (ac *AutoConfig) updateJoinAddressesInConfig(opts AutoConfigOptions, conf *config.Config) error {
	joinAddrs, err := ac.delegate.DatacenterJoinAddresses(opts.SegmentName)
	if err != nil {
		return err
	}

	if conf.Gossip == nil {
		conf.Gossip = &config.Gossip{}
	}

	conf.Gossip.RetryJoinLAN = joinAddrs
	return nil
}

// updateGossipEncryptionInConfig will populate the gossip encryption configuration settings
func (ac *AutoConfig) updateGossipEncryptionInConfig(_ AutoConfigOptions, conf *config.Config) error {
	// Add gossip encryption settings if there is any key loaded
	memberlistConfig := ac.getDelegateConfig().SerfLANConfig.MemberlistConfig
	if lanKeyring := memberlistConfig.Keyring; lanKeyring != nil {
		if conf.Gossip == nil {
			conf.Gossip = &config.Gossip{}
		}
		if conf.Gossip.Encryption == nil {
			conf.Gossip.Encryption = &config.GossipEncryption{}
		}

		pk := lanKeyring.GetPrimaryKey()
		if len(pk) > 0 {
			conf.Gossip.Encryption.Key = base64.StdEncoding.EncodeToString(pk)
		}

		conf.Gossip.Encryption.VerifyIncoming = memberlistConfig.GossipVerifyIncoming
		conf.Gossip.Encryption.VerifyOutgoing = memberlistConfig.GossipVerifyOutgoing
	}

	return nil
}

// updateTLSSettingsInConfig will populate the TLS configuration settings but will not
// populate leaf or ca certficiates.
func (ac *AutoConfig) updateTLSSettingsInConfig(_ AutoConfigOptions, conf *config.Config) error {
	tlsConfigurator := ac.delegate.TLSConfigurator()
	if tlsConfigurator == nil {
		// TLS is not enabled?
		return nil
	}

	// add in TLS configuration
	if conf.TLS == nil {
		conf.TLS = &config.TLS{}
	}

	conf.TLS.VerifyServerHostname = tlsConfigurator.VerifyServerHostname()
	base := tlsConfigurator.Base()
	conf.TLS.VerifyOutgoing = base.VerifyOutgoing
	conf.TLS.MinVersion = base.TLSMinVersion
	conf.TLS.PreferServerCipherSuites = base.PreferServerCipherSuites

	var err error
	conf.TLS.CipherSuites, err = tlsutil.CipherString(base.CipherSuites)
	return err
}

// baseConfig will populate the configuration with some base settings such as the
// datacenter names, node name etc.
func (ac *AutoConfig) baseConfig(opts AutoConfigOptions, conf *config.Config) error {
	delegateConf := ac.getDelegateConfig()

	if opts.NodeName == "" {
		return fmt.Errorf("Cannot generate auto config response without a node name")
	}

	conf.Datacenter = delegateConf.Datacenter
	conf.PrimaryDatacenter = delegateConf.PrimaryDatacenter
	conf.NodeName = opts.NodeName
	conf.SegmentName = opts.SegmentName

	return nil
}

type autoConfigUpdater func(c *AutoConfig, opts AutoConfigOptions, conf *config.Config) error

var (
	// variable holding the list of config updating functions to execute when generating
	// the auto config response. This will allow for more easily adding extra self-contained
	// configurators here in the future.
	autoConfigUpdaters []autoConfigUpdater = []autoConfigUpdater{
		(*AutoConfig).baseConfig,
		(*AutoConfig).updateJoinAddressesInConfig,
		(*AutoConfig).updateGossipEncryptionInConfig,
		(*AutoConfig).updateTLSSettingsInConfig,
		(*AutoConfig).updateACLsInConfig,
		(*AutoConfig).updateTLSCertificatesInConfig,
	}
)

// AgentAutoConfig will authorize the incoming request and then generate the configuration
// to push down to the client
func (ac *AutoConfig) InitialConfiguration(req *agentpb.AutoConfigRequest, resp *agentpb.AutoConfigResponse) error {
	delegateConf := ac.getDelegateConfig()

	// default the datacenter to our datacenter - agents do not have to specify this as they may not
	// yet know the datacenter name they are going to be in.
	if req.Datacenter == "" {
		req.Datacenter = delegateConf.Datacenter
	}

	// TODO (autoconf) Is performing auto configuration over the WAN really a bad idea?
	if req.Datacenter != delegateConf.Datacenter {
		return fmt.Errorf("invalid datacenter %q - agent auto configuration cannot target a remote datacenter", req.Datacenter)
	}

	// forward to the leader
	if done, err := ac.delegate.ForwardRPC("AutoConfig.InitialConfiguration", req, req, resp); done {
		return err
	}

	// TODO (autoconf) maybe panic instead?
	if ac.authorizer == nil {
		return fmt.Errorf("No Auto Config authorizer is configured")
	}

	// authorize the request with the configured authorizer
	opts, err := ac.authorizer.Authorize(req)
	if err != nil {
		return err
	}

	conf := &config.Config{}

	// update all the configurations
	for _, configFn := range autoConfigUpdaters {
		if err := configFn(ac, opts, conf); err != nil {
			return err
		}
	}

	resp.Config = conf
	return nil
}
