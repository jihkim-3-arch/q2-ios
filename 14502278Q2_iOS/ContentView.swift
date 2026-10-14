//  App name: 14502278Q2_iOS
//  Public-key encryption demo — key pair in Keychain + Secure Enclave
//  Keychain tag = student ID (14502278)

import SwiftUI
import Security

struct ContentView: View {
    @State private var message = ""
    @State private var encryptedText = ""
    @State private var publicKeyText = ""
    @State private var decryptedText = ""
    @State private var cipherData: Data?

    // Keychain tag = student ID
    private let keyTag = "14502278".data(using: .utf8)!
    // Secure Enclave only supports EC P-256 -> ECIES (ECDH + AES-GCM)
    private let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("14502278Q2_iOS").font(.title2).bold()

                // 1. Text Field
                TextField("Enter your message", text: $message)
                    .textFieldStyle(.roundedBorder)

                // 2. Encrypt button
                Button("Encrypt") { encrypt() }
                    .buttonStyle(.borderedProminent)

                // 3. Encrypted message view
                Text("Encrypted message (Base64):").bold()
                Text(encryptedText)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8).background(Color.gray.opacity(0.15))

                // 4. Public key view
                Text("Public key (Base64):").bold()
                Text(publicKeyText)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8).background(Color.gray.opacity(0.15))

                // 5. Decrypt button
                Button("Decrypt") { decrypt() }
                    .buttonStyle(.borderedProminent)

                // 6. Decrypted message view
                Text("Decrypted message:").bold()
                Text(decryptedText)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8).background(Color.gray.opacity(0.15))
            }
            .padding()
        }
    }

    // MARK: - Key management (Keychain + Secure Enclave)

    private func getOrCreatePrivateKey() throws -> SecKey {
        // 1) Look up an existing key with our tag in the Keychain
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess {
            return item as! SecKey
        }

        // 2) Otherwise create a new P-256 key pair
        var error: Unmanaged<CFError>?
        var privateAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,       // store in Keychain
            kSecAttrApplicationTag as String: keyTag   // tag = student ID
        ]
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]

        #if targetEnvironment(simulator)
        // The Simulator has no Secure Enclave hardware -> key lives in Keychain only
        privateAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        #else
        // Real device: private key is generated and kept inside the Secure Enclave
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            &error) else { throw error!.takeRetainedValue() as Error }
        privateAttrs[kSecAttrAccessControl as String] = access
        attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        #endif

        attributes[kSecPrivateKeyAttrs as String] = privateAttrs

        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }

    // MARK: - Encrypt with public key

    private func encrypt() {
        do {
            let privateKey = try getOrCreatePrivateKey()
            guard let publicKey = SecKeyCopyPublicKey(privateKey),
                  SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
                encryptedText = "Algorithm not supported"; return
            }

            var error: Unmanaged<CFError>?
            guard let cipher = SecKeyCreateEncryptedData(
                publicKey, algorithm, Data(message.utf8) as CFData, &error) as Data? else {
                throw error!.takeRetainedValue() as Error
            }
            cipherData = cipher
            encryptedText = cipher.base64EncodedString()

            // Public key CAN be exported (65-byte ANSI X9.63 format)
            if let pubData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? {
                publicKeyText = pubData.base64EncodedString()
            }
            decryptedText = ""
        } catch {
            encryptedText = "Encryption error: \(error.localizedDescription)"
        }
    }

    // MARK: - Decrypt with private key (operation happens inside Secure Enclave)

    private func decrypt() {
        guard let cipher = cipherData else { decryptedText = "Encrypt first"; return }
        do {
            let privateKey = try getOrCreatePrivateKey()
            guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
                decryptedText = "Algorithm not supported"; return
            }
            var error: Unmanaged<CFError>?
            guard let plain = SecKeyCreateDecryptedData(
                privateKey, algorithm, cipher as CFData, &error) as Data? else {
                throw error!.takeRetainedValue() as Error
            }
            decryptedText = String(decoding: plain, as: UTF8.self)
        } catch {
            decryptedText = "Decryption error: \(error.localizedDescription)"
        }
    }
}

#Preview { ContentView() }
