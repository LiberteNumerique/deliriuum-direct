import Foundation
import NetworkExtension
import WireGuardKit

final class PacketTunnelProvider: NEPacketTunnelProvider {

    private lazy var wireGuardAdapter: WireGuardAdapter = {
        WireGuardAdapter(with: self) { level, message in
            switch level {
            case .verbose:
                NSLog("[Deliriuum/WireGuard] %@", message)

            case .error:
                NSLog("[Deliriuum/WireGuard ERROR] %@", message)
            }
        }
    }()

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard
            let proto = protocolConfiguration as? NETunnelProviderProtocol,
            let providerConfig = proto.providerConfiguration,
            let wireguardConfig = providerConfig["wireguardConfig"] as? String,
            !wireguardConfig.isEmpty
        else {
            completionHandler(makeError(
                code: 1,
                message: "Configuration WireGuard absente."
            ))
            return
        }

        /*
         Ne jamais logger wireguardConfig :
         elle contient la clé privée WireGuard.
        */

        do {
            let tunnelConfiguration = try parseWireGuardConfig(wireguardConfig)

            NSLog("[Deliriuum] Configuration WireGuard analysée")
            NSLog(
                "[Deliriuum] %d peer(s)",
                tunnelConfiguration.peers.count
            )

            wireGuardAdapter.start(
                tunnelConfiguration: tunnelConfiguration
            ) { error in

                if let error {
                    NSLog(
                        "[Deliriuum/WireGuard ERROR] Démarrage impossible : %@",
                        String(describing: error)
                    )

                    completionHandler(error)
                    return
                }

                NSLog("[Deliriuum] Tunnel WireGuard démarré")
                completionHandler(nil)
            }

        } catch {
            NSLog(
                "[Deliriuum] Configuration invalide : %@",
                error.localizedDescription
            )

            completionHandler(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        NSLog(
            "[Deliriuum] Arrêt du tunnel, raison=%d",
            reason.rawValue
        )

        wireGuardAdapter.stop { error in
            if let error {
                NSLog(
                    "[Deliriuum/WireGuard ERROR] Arrêt : %@",
                    String(describing: error)
                )
            }

            completionHandler()
        }
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        completionHandler?(messageData)
    }

    override func sleep(
        completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }

    override func wake() {
    }

    // MARK: - Parsing WireGuard

    private func parseWireGuardConfig(
        _ text: String
    ) throws -> TunnelConfiguration {

        enum Section {
            case none
            case interface
            case peer
        }

        var section: Section = .none

        var privateKeyString: String?
        var addresses: [String] = []
        var dnsServers: [String] = []
        var mtu: UInt16?

        struct RawPeer {
            var publicKey: String?
            var preSharedKey: String?
            var allowedIPs: [String] = []
            var endpoint: String?
            var persistentKeepAlive: UInt16?
        }

        var peers: [RawPeer] = []
        var currentPeer: RawPeer?

        func finishPeer() {
            if let peer = currentPeer {
                peers.append(peer)
            }
            currentPeer = nil
        }

        for rawLine in text.components(separatedBy: .newlines) {

            let line = rawLine
                .trimmingCharacters(in: .whitespacesAndNewlines)

            if line.isEmpty || line.hasPrefix("#") {
                continue
            }

            if line == "[Interface]" {
                finishPeer()
                section = .interface
                continue
            }

            if line == "[Peer]" {
                finishPeer()
                currentPeer = RawPeer()
                section = .peer
                continue
            }

            guard let equal = line.firstIndex(of: "=") else {
                continue
            }

            let key = String(line[..<equal])
                .trimmingCharacters(in: .whitespaces)

            let value = String(line[line.index(after: equal)...])
                .trimmingCharacters(in: .whitespaces)

            switch section {

            case .interface:

                switch key.lowercased() {

                case "privatekey":
                    privateKeyString = value

                case "address":
                    addresses.append(
                        contentsOf: splitCommaSeparated(value)
                    )

                case "dns":
                    dnsServers.append(
                        contentsOf: splitCommaSeparated(value)
                    )

                case "mtu":
                    mtu = UInt16(value)

                default:
                    break
                }

            case .peer:

                guard currentPeer != nil else {
                    continue
                }

                switch key.lowercased() {

                case "publickey":
                    currentPeer?.publicKey = value

                case "presharedkey":
                    currentPeer?.preSharedKey = value

                case "allowedips":
                    currentPeer?.allowedIPs.append(
                        contentsOf: splitCommaSeparated(value)
                    )

                case "endpoint":
                    currentPeer?.endpoint = value

                case "persistentkeepalive":
                    currentPeer?.persistentKeepAlive = UInt16(value)

                default:
                    break
                }

            case .none:
                continue
            }
        }

        finishPeer()

        guard
            let privateKeyString,
            let privateKey = PrivateKey(base64Key: privateKeyString)
        else {
            throw makeError(
                code: 10,
                message: "Clé privée WireGuard invalide."
            )
        }

        var interface = InterfaceConfiguration(
            privateKey: privateKey
        )

        for value in addresses {
            guard let address = IPAddressRange(from: value) else {
                throw makeError(
                    code: 11,
                    message: "Adresse WireGuard invalide : \(value)"
                )
            }

            interface.addresses.append(address)
        }

        guard !interface.addresses.isEmpty else {
            throw makeError(
                code: 12,
                message: "Aucune adresse WireGuard configurée."
            )
        }

        for value in dnsServers {
            guard let dns = DNSServer(from: value) else {
                throw makeError(
                    code: 13,
                    message: "Serveur DNS invalide : \(value)"
                )
            }

            interface.dns.append(dns)
        }

        interface.mtu = mtu

        var peerConfigurations: [PeerConfiguration] = []

        for rawPeer in peers {

            guard
                let publicKeyString = rawPeer.publicKey,
                let publicKey = PublicKey(
                    base64Key: publicKeyString
                )
            else {
                throw makeError(
                    code: 20,
                    message: "Clé publique WireGuard invalide."
                )
            }

            var peer = PeerConfiguration(
                publicKey: publicKey
            )

            if let preSharedKeyString = rawPeer.preSharedKey {

                guard let preSharedKey = PreSharedKey(
                    base64Key: preSharedKeyString
                ) else {
                    throw makeError(
                        code: 21,
                        message: "Clé pré-partagée WireGuard invalide."
                    )
                }

                peer.preSharedKey = preSharedKey
            }

            for value in rawPeer.allowedIPs {

                guard let allowedIP = IPAddressRange(from: value) else {
                    throw makeError(
                        code: 22,
                        message: "AllowedIPs invalide : \(value)"
                    )
                }

                peer.allowedIPs.append(allowedIP)
            }

            guard !peer.allowedIPs.isEmpty else {
                throw makeError(
                    code: 23,
                    message: "AllowedIPs absent."
                )
            }

            if let endpointString = rawPeer.endpoint {

                guard let endpoint = Endpoint(from: endpointString) else {
                    throw makeError(
                        code: 24,
                        message: "Endpoint WireGuard invalide : \(endpointString)"
                    )
                }

                peer.endpoint = endpoint
            }

            peer.persistentKeepAlive =
                rawPeer.persistentKeepAlive

            peerConfigurations.append(peer)
        }

        guard !peerConfigurations.isEmpty else {
            throw makeError(
                code: 25,
                message: "Aucun peer WireGuard configuré."
            )
        }

        return TunnelConfiguration(
            name: "Deliriuum Direct",
            interface: interface,
            peers: peerConfigurations
        )
    }

    private func splitCommaSeparated(
        _ value: String
    ) -> [String] {
        value
            .split(separator: ",")
            .map {
                String($0)
                    .trimmingCharacters(in: .whitespaces)
            }
            .filter { !$0.isEmpty }
    }

    private func makeError(
        code: Int,
        message: String
    ) -> NSError {
        NSError(
            domain: "com.deliriuum.direct",
            code: code,
            userInfo: [
                NSLocalizedDescriptionKey: message
            ]
        )
    }
}
