import Foundation
import NetworkExtension
import Combine

@MainActor
final class VPNManager: ObservableObject {

    static let shared = VPNManager()

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var lastError: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    private init() {
        Task {
            await load()
        }
    }

    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()

            manager = managers.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == "com.deliriuum.direct.PacketTunnel"
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
        ) { _ in
            NotificationCenter.default.post(
                name: Notification.Name("DeliriuumVPNStatusRefresh"),
                object: nil
            )
        }

        NotificationCenter.default.addObserver(
            forName: Notification.Name("DeliriuumVPNStatusRefresh"),
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.status = self?.manager?.connection.status ?? .invalid
        }
    }

    func installConfiguration() async throws {
        guard let manager else {
            throw NSError(
                domain: "DeliriuumDirect",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Gestionnaire VPN indisponible."]
            )
        }

        let proto = NETunnelProviderProtocol()

        proto.providerBundleIdentifier =
            "com.deliriuum.direct.PacketTunnel"

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
            guard let manager else {
                throw NSError(
                    domain: "DeliriuumDirect",
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Gestionnaire VPN indisponible."]
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
