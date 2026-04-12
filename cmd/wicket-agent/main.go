// wicket-agent runs on a remote server and manages a local WireGuard interface
// under instruction from the Wicket core server.
//
// Usage:
//
//	wicket-agent --server wss://admin.vpn.example.com --token <token> \
//	             --interface wg1 --listen-port 51820
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/wicket-vpn/wicket/internal/agent"
	"github.com/wicket-vpn/wicket/internal/wireguard"
)

var (
	serverURL         = flag.String("server", "", "Wicket admin WebSocket URL e.g. wss://admin.vpn.example.com")
	token             = flag.String("token", "", "Agent authentication token")
	iface             = flag.String("interface", "wg1", "WireGuard interface name to manage")
	listenPort        = flag.Int("listen-port", 51820, "WireGuard listen port")
	privateKey        = flag.String("private-key", "", "WireGuard private key (auto-generated if empty)")
	keepPeersOnDiscon = flag.Bool("keep-peers-on-disconnect", true, "Keep WireGuard peers when disconnected from Wicket (recommended)")
	generateKey       = flag.Bool("generate-key", false, "Generate a WireGuard private key and print it, then exit")
	version           = "dev"
)

func main() {
	flag.Parse()

	// --generate-key: print a new private key and exit (used by install scripts)
	if *generateKey {
		priv, pub, err := wireguard.GenerateKeypair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "generating keypair: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("PRIVATE_KEY=%s\n", priv)
		fmt.Fprintf(os.Stderr, "Public key: %s\n", pub)
		return
	}

	if *serverURL == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "usage: wicket-agent --server <wss://...> --token <token> [--interface wg1] [--listen-port 51820] [--private-key <key>]")
		os.Exit(1)
	}

	privKey := *privateKey
	if privKey == "" {
		var pubKey string
		var err error
		privKey, pubKey, err = wireguard.GenerateKeypair()
		if err != nil {
			log.Fatalf("generating WireGuard keypair: %v", err)
		}
		log.Printf("Generated WireGuard keypair")
		log.Printf("Public key: %s", pubKey)
		log.Printf("Store the private key with --private-key to persist it across restarts")
	}

	if err := setupInterface(*iface); err != nil {
		log.Fatalf("setting up WireGuard interface %s: %v", *iface, err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("wicket-agent %s starting, interface: %s, server: %s", version, *iface, *serverURL)
	runLoop(ctx, privKey)
}

// runLoop connects to Wicket and reconnects on disconnect.
func runLoop(ctx context.Context, privKey string) {
	for {
		if err := connect(ctx, privKey); err != nil && ctx.Err() == nil {
			log.Printf("Connection lost: %v — reconnecting in 10s", err)
			if !*keepPeersOnDiscon {
				log.Printf("Clearing peers due to --keep-peers-on-disconnect=false")
				if pm, err := wireguard.NewLocalPeerManager(*iface); err == nil {
					keys, _ := pm.ListPeers()
					for _, k := range keys {
						_ = pm.RemovePeer(k)
					}
					pm.Close()
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
		if ctx.Err() != nil {
			log.Println("Agent shutting down")
			return
		}
	}
}

func connect(ctx context.Context, privKey string) error {
	wsURL := *serverURL + "/agent/connect"
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: map[string][]string{
			"Authorization": {"Bearer " + *token},
		},
	})
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", wsURL, err)
	}
	defer conn.CloseNow()

	log.Println("Connected to Wicket core")

	// Derive public key from private key to send in ready message.
	// Wicket stores this and embeds it in device configs so clients
	// connect to the right server when using a remote agent.
	pubKey, err := wireguard.ServerPublicKey(privKey)
	if err != nil {
		return fmt.Errorf("deriving public key: %w", err)
	}

	// Send ready message
	hostname, _ := os.Hostname()
	if err := wsjson.Write(ctx, conn, agent.Envelope{
		Type: agent.MsgReady,
		Payload: agent.ReadyPayload{
			AgentVersion: version,
			Hostname:     hostname,
			WGPublicKey:  pubKey,
			ConnectedAt:  time.Now(),
		},
	}); err != nil {
		return fmt.Errorf("sending ready: %w", err)
	}

	// Initialise local WireGuard peer manager
	pm, err := wireguard.NewLocalPeerManager(*iface)
	if err != nil {
		return fmt.Errorf("opening WireGuard interface %s: %w", *iface, err)
	}
	defer pm.Close()

	if err := pm.ConfigureServer(privKey, *listenPort); err != nil {
		return fmt.Errorf("configuring WireGuard: %w", err)
	}

	// Message loop
	for {
		var env agent.Envelope
		if err := wsjson.Read(ctx, conn, &env); err != nil {
			return fmt.Errorf("reading message: %w", err)
		}
		if err := handleMessage(ctx, conn, pm, env); err != nil {
			log.Printf("Error handling %s: %v", env.Type, err)
		}
	}
}

func handleMessage(ctx context.Context, conn *websocket.Conn, pm wireguard.PeerManager, env agent.Envelope) error {
	switch env.Type {
	case agent.MsgSync:
		payload, err := decodePayload[agent.SyncPayload](env.Payload)
		if err != nil {
			return fmt.Errorf("decoding sync: %w", err)
		}
		log.Printf("Sync received: %d peers", len(payload.Peers))
		return applySync(pm, payload)

	case agent.MsgPeerAdd:
		payload, err := decodePayload[agent.PeerConfig](env.Payload)
		if err != nil {
			return fmt.Errorf("decoding peer.add: %w", err)
		}
		log.Printf("Adding peer: %s (%s)", payload.DeviceName, payload.AssignedIP)
		opErr := addPeer(pm, payload)
		return sendAck(ctx, conn, env.MsgID, opErr)

	case agent.MsgPeerRemove:
		payload, err := decodePayload[agent.PeerRemovePayload](env.Payload)
		if err != nil {
			return fmt.Errorf("decoding peer.remove: %w", err)
		}
		log.Printf("Removing peer: %s (device %s)", payload.PublicKey[:8], payload.DeviceID[:8])
		opErr := pm.RemovePeer(payload.PublicKey)
		return sendAck(ctx, conn, env.MsgID, opErr)

	default:
		log.Printf("Unknown message type: %s", env.Type)
	}
	return nil
}

// applySync reconciles the full peer list from Wicket.
func applySync(pm wireguard.PeerManager, payload agent.SyncPayload) error {
	// Set the interface IP address if provided in the sync payload.
	// This ensures the agent's WireGuard interface has the correct address
	// (the .1 of its VPN pool) for routing to work.
	if payload.InterfaceAddress != "" {
		if err := exec.Command("ip", "addr", "replace", payload.InterfaceAddress,
			"dev", *iface).Run(); err != nil {
			log.Printf("Warning: setting interface address %s: %v", payload.InterfaceAddress, err)
		} else {
			log.Printf("Interface %s address set to %s", *iface, payload.InterfaceAddress)
		}
	}

	currentKeys, err := pm.ListPeers()
	if err != nil {
		return fmt.Errorf("listing current peers: %w", err)
	}
	current := make(map[string]bool, len(currentKeys))
	for _, k := range currentKeys {
		current[k] = true
	}

	desired := make(map[string]bool, len(payload.Peers))
	for _, p := range payload.Peers {
		desired[p.PublicKey] = true
		if err := addPeer(pm, p); err != nil {
			log.Printf("Failed to add peer %s: %v", p.DeviceName, err)
		}
	}

	// Remove peers that are no longer in the desired state
	for key := range current {
		if !desired[key] {
			log.Printf("Removing stale peer: %s...", key[:8])
			if err := pm.RemovePeer(key); err != nil {
				log.Printf("Failed to remove peer: %v", err)
			}
		}
	}
	log.Printf("Sync complete: %d active peers", len(desired))
	return nil
}

func addPeer(pm wireguard.PeerManager, p agent.PeerConfig) error {
	ipStr := p.AssignedIP
	if ip, _, err := net.ParseCIDR(p.AssignedIP); err == nil {
		ipStr = ip.String()
	}
	hostIP := net.ParseIP(ipStr)
	if hostIP == nil {
		return fmt.Errorf("invalid assigned IP %q", p.AssignedIP)
	}

	allowedIPs := make([]net.IPNet, 0, len(p.AllowedIPs))
	for _, cidr := range p.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			allowedIPs = append(allowedIPs, *ipNet)
		}
	}

	return pm.AddPeer(wireguard.PeerConfig{
		PublicKey:  p.PublicKey,
		AssignedIP: hostIP,
		AllowedIPs: allowedIPs,
	})
}

func sendAck(ctx context.Context, conn *websocket.Conn, msgID string, opErr error) error {
	var ackPayload agent.AckPayload
	if opErr != nil {
		ackPayload = agent.AckPayload{MsgID: msgID, Success: false, Error: opErr.Error()}
	} else {
		ackPayload = agent.AckPayload{MsgID: msgID, Success: true}
	}
	return wsjson.Write(ctx, conn, agent.Envelope{
		Type:    agent.MsgAck,
		MsgID:   msgID,
		Payload: ackPayload,
	})
}

// setupInterface creates the WireGuard interface if it doesn't exist.
func setupInterface(iface string) error {
	if err := exec.Command("ip", "link", "show", iface).Run(); err != nil {
		// Interface doesn't exist — create it
		if err := exec.Command("modprobe", "wireguard").Run(); err != nil {
			log.Printf("Warning: modprobe wireguard failed (may already be loaded): %v", err)
		}
		if err := exec.Command("ip", "link", "add", iface, "type", "wireguard").Run(); err != nil {
			return fmt.Errorf("creating WireGuard interface %s: %w", iface, err)
		}
		log.Printf("Created WireGuard interface %s", iface)
	}
	if err := exec.Command("ip", "link", "set", iface, "up").Run(); err != nil {
		return fmt.Errorf("bringing up %s: %w", iface, err)
	}
	// Enable IP forwarding
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
	return nil
}

// decodePayload round-trips through JSON to decode the any payload into T.
func decodePayload[T any](payload any) (T, error) {
	var result T
	b, err := json.Marshal(payload)
	if err != nil {
		return result, err
	}
	return result, json.Unmarshal(b, &result)
}
