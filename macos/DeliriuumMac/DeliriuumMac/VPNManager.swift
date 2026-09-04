import Foundation
import NetworkExtension
import Combine
import SystemExtensions

@MainActor
final class VPNManager: NSObject, ObservableObject {

    static let shared = VPNManager()

    private static let packetTunnelBundleIdentifier =
        "com.deliriuum.direct.PacketTunnel"

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var lastError: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    private var activationContinuation:
        CheckedContinuation<Void, Error>?

    private override init() {
        super.init()

        Task {
            await load()
        }
    }

    func load() async {
        do {
            let managers =
                try await NETunnelProviderManager.loadAllFromPreferences()

            manager = managers.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier
                    == Self.packetTunnelBundleIdentifier
            })

            if manager == nil {
                manager = NETunnelProviderManager()
            }

            installStatusObserver()
            refreshStatus()

        } catch {
            lastError = error.localizedDescription
        }
    }

    private func installStatusObserver() {

        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }

        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.refreshStatus()
            }
        }
    }

    private func activateSystemExtension() async throws {

        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in

            guard activationContinuation == nil else {
                continuation.resume(
                    throwing: NSError(
                        domain: "DeliriuumDirect",
                        code: 10,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                "Une activation de l’extension VPN est déjà en cours."
                        ]
                    )
                )
                return
            }

            activationContinuation = continuation

            let request =
                OSSystemExtensionRequest.activationRequest(
                    forExtensionWithIdentifier:
                        Self.packetTunnelBundleIdentifier,
                    queue: .main
                )

            request.delegate = self

            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    func installConfiguration() async throws {

        guard let manager else {
            throw NSError(
                domain: "DeliriuumDirect",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Gestionnaire VPN indisponible."
                ]
            )
        }

        let proto = NETunnelProviderProtocol()

        proto.providerBundleIdentifier =
            Self.packetTunnelBundleIdentifier

        proto.serverAddress = "Deliriuum Direct"

        manager.protocolConfiguration = proto
        manager.localizedDescription = "Deliriuum Direct"
        manager.isEnabled = true

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()

        refreshStatus()
    }

    func connect() async {

        lastError = nil

        do {
            try await activateSystemExtension()

            guard let manager else {
                throw NSError(
                    domain: "DeliriuumDirect",
                    code: 2,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "Gestionnaire VPN indisponible."
                    ]
                )
            }

            if manager.protocolConfiguration == nil {
                try await installConfiguration()
            }

            try manager.connection.startVPNTunnel()

            refreshStatus()

        } catch {
            lastError = error.localizedDescription
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
        refreshStatus()
    }

    private func refreshStatus() {
        status = manager?.connection.status ?? .invalid
    }
}


// MARK: - System Extension

extension VPNManager: OSSystemExtensionRequestDelegate {

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result:
            OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in

            guard let continuation = activationContinuation else {
                return
            }

            activationContinuation = nil

            switch result {
            case .completed:
                continuation.resume()

            case .willCompleteAfterReboot:
                continuation.resume(
                    throwing: NSError(
                        domain: "DeliriuumDirect",
                        code: 11,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                "L’activation de l’extension VPN sera terminée après redémarrage du Mac."
                        ]
                    )
                )

            @unknown default:
                continuation.resume(
                    throwing: NSError(
                        domain: "DeliriuumDirect",
                        code: 12,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                "Résultat inconnu lors de l’activation de l’extension VPN."
                        ]
                    )
                )
            }
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        Task { @MainActor in

            guard let continuation = activationContinuation else {
                return
            }

            activationContinuation = nil
            continuation.resume(throwing: error)
        }
    }

    nonisolated func requestNeedsUserApproval(
        _ request: OSSystemExtensionRequest
    ) {
        // macOS affiche lui-même la demande d'autorisation.
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing:
            OSSystemExtensionProperties,
        withExtension ext:
            OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {

        return .replace
    }
}
