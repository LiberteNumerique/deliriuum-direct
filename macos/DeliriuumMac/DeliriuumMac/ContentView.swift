import SwiftUI
import NetworkExtension

struct ContentView: View {

    @StateObject private var vpn = VPNManager.shared
    @State private var working = false

    var body: some View {
        VStack(spacing: 24) {

            Image(systemName: vpn.status == .connected ? "shield.fill" : "shield")
                .font(.system(size: 54))

            Text("Deliriuum Direct")
                .font(.title)
                .fontWeight(.semibold)

            Text(statusText)
                .foregroundStyle(.secondary)

            Button {
                Task {
                    working = true
                    defer { working = false }

                    do {
                        switch vpn.status {
                        case .connected, .connecting, .reasserting:
                            vpn.disconnect()

                        default:
                            try await vpn.connect()
                        }
                    } catch {
                        // L'erreur est déjà conservée dans VPNManager.
                    }
                }
            } label: {
                Text(buttonText)
                    .frame(minWidth: 180)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(working)

            if let error = vpn.lastError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 360)
            }
        }
        .padding(40)
        .frame(width: 420, height: 360)
    }

    private var statusText: String {
        switch vpn.status {
        case .invalid:
            return "VPN non configuré"
        case .disconnected:
            return "VPN déconnecté"
        case .connecting:
            return "Connexion…"
        case .connected:
            return "VPN connecté"
        case .reasserting:
            return "Reconnexion…"
        case .disconnecting:
            return "Déconnexion…"
        @unknown default:
            return "État inconnu"
        }
    }

    private var buttonText: String {
        if working {
            return "Veuillez patienter…"
        }

        switch vpn.status {
        case .connected, .connecting, .reasserting:
            return "Déconnecter"
        default:
            return "Protéger"
        }
    }
}

#Preview {
    ContentView()
}
