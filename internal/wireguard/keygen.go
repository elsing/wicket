package wireguard

import (
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GenerateKeypair generates a new WireGuard private/public key pair.
// Returns (privateKeyBase64, publicKeyBase64, error).
// The private key must be treated as a secret and discarded after use.
func GenerateKeypair() (privateKey, publicKey string, err error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generating WireGuard keypair: %w", err)
	}
	return key.String(), key.PublicKey().String(), nil
}

// ClientConfigParams holds everything needed to render a WireGuard .conf file
// for a client device.
type ClientConfigParams struct {
	// PrivateKey is the client's private key (base64). Never stored server-side.
	PrivateKey string
	// AssignedIP is the client's VPN address, e.g. "10.10.0.2".
	AssignedIP string
	// DNS servers to push to the client, e.g. ["1.1.1.1", "1.0.0.1"].
	DNS []string
	// ServerPublicKey is the server's WireGuard public key (base64).
	ServerPublicKey string
	// ServerEndpoint is the server's public host:port, e.g. "vpn.example.com:51820".
	ServerEndpoint string
	// AllowedIPs is the list of CIDRs routed through the VPN.
	AllowedIPs []string
	// MTU for the interface. 0 = omit from config (client uses default).
	MTU int
}

// BuildClientConfig assembles a WireGuard .conf file from the given parameters.
// This is the file the user downloads — it is generated once and not stored.
func BuildClientConfig(p ClientConfigParams) string {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", p.PrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s/32\n", p.AssignedIP))

	if len(p.DNS) > 0 {
		sb.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(p.DNS, ", ")))
	}

	if p.MTU > 0 {
		sb.WriteString(fmt.Sprintf("MTU = %d\n", p.MTU))
	}

	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", p.ServerPublicKey))
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", p.ServerEndpoint))

	if len(p.AllowedIPs) > 0 {
		sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", ")))
	}

	// PersistentKeepalive keeps the session alive through NAT.
	sb.WriteString("PersistentKeepalive = 25\n")

	return sb.String()
}
