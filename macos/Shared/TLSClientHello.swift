import Foundation

/// First TLS record only. Never release bytes while this result is needMore.
/// Fragmented TLS records, malformed and oversized handshakes fail closed.
/// ECH is opaque: GREASE cannot be distinguished from a real encrypted hello.
enum TLSHelloResult: Equatable {
    case needMore(Int)
    case serverName(String, echPresent: Bool = false)
    case deny(String)
}

enum TLSClientHello {
    static let maximumBytes = 16_384

    static func inspect(_ data: Data) -> TLSHelloResult {
        guard data.count <= maximumBytes else { return .deny("tls_unparsed") }
        let bytes = Array(data)
        if let first = bytes.first, first != 0x16 { return .deny("not_tls") }
        guard bytes.count >= 5 else { return .needMore(5) }
        guard bytes[1] == 3, (1...3).contains(bytes[2]) else { return .deny("not_tls") }
        func uint16(_ index: Int) -> Int { Int(bytes[index]) * 256 + Int(bytes[index + 1]) }
        let recordEnd = 5 + uint16(3)
        guard recordEnd >= 9, recordEnd <= maximumBytes else { return .deny("tls_unparsed") }
        guard bytes.count >= recordEnd else { return .needMore(recordEnd) }
        guard bytes[5] == 1 else { return .deny("tls_unparsed") }
        let helloEnd = 9 + Int(bytes[6]) * 65_536 + Int(bytes[7]) * 256 + Int(bytes[8])
        guard helloEnd == recordEnd, helloEnd >= 44,
              bytes[9] == 3, (1...3).contains(bytes[10]) else { return .deny("tls_unparsed") }
        var cursor = 43 // legacy_version + random, after the handshake header
        let sessionLength = Int(bytes[cursor]); cursor += 1
        guard sessionLength <= 32, cursor + sessionLength + 2 <= helloEnd else { return .deny("tls_unparsed") }
        cursor += sessionLength
        let cipherLength = uint16(cursor); cursor += 2
        guard cipherLength >= 2, cipherLength % 2 == 0,
              cursor + cipherLength + 1 <= helloEnd else { return .deny("tls_unparsed") }
        cursor += cipherLength
        let compressionLength = Int(bytes[cursor]); cursor += 1
        guard compressionLength > 0, cursor + compressionLength <= helloEnd else { return .deny("tls_unparsed") }
        cursor += compressionLength
        if cursor == helloEnd { return .deny("sni_missing") }
        guard cursor + 2 <= helloEnd else { return .deny("tls_unparsed") }
        let extensionEnd = cursor + 2 + uint16(cursor); cursor += 2
        guard extensionEnd == helloEnd else { return .deny("tls_unparsed") }
        var seen = Set<Int>(), serverName: String?
        while cursor < extensionEnd {
            guard cursor + 4 <= extensionEnd else { return .deny("tls_unparsed") }
            let kind = uint16(cursor), length = uint16(cursor + 2)
            cursor += 4
            let end = cursor + length
            guard end <= extensionEnd, seen.insert(kind).inserted else { return .deny("tls_unparsed") }
            // Preserve ECH presence for diagnostics. Only the outer SNI can be
            // checked; permitting an ECH front end is a domain-fronting limit.
            if kind == 0 {
                guard length >= 5, uint16(cursor) == length - 2 else { return .deny("tls_unparsed") }
                cursor += 2
                // Only one host_name entry is supported; reject ambiguous lists.
                guard bytes[cursor] == 0, uint16(cursor + 1) == end - cursor - 3 else {
                    return .deny("tls_unparsed")
                }
                cursor += 3
                let nameBytes = bytes[cursor..<end]
                guard nameBytes.allSatisfy({ $0 > 0 && $0 < 128 }),
                      let name = String(bytes: nameBytes, encoding: .utf8).flatMap(normalizeHost),
                      !looksNumeric(name) else { return .deny("tls_unparsed") }
                serverName = name
            }
            cursor = end
        }
        return serverName.map { .serverName($0, echPresent: seen.contains(0xfe0d)) } ?? .deny("sni_missing")
    }
}

/// Bounded transient peek data. Handles cumulative or contiguous callback
/// slices without trusting offsets or allowing a prefix to be replaced.
struct TLSInspection {
    private var bytes = Data()
    let expectedHost: String
    private(set) var echPresent = false

    mutating func receive(_ data: Data, offset: Int) -> TLSHelloResult {
        guard offset >= 0, offset <= bytes.count, data.count <= TLSClientHello.maximumBytes - offset else {
            return .deny("tls_unparsed")
        }
        let overlap = min(data.count, bytes.count - offset)
        guard bytes.subdata(in: offset..<(offset + overlap)) == data.prefix(overlap) else {
            return .deny("tls_unparsed")
        }
        bytes.append(data.dropFirst(overlap))
        switch TLSClientHello.inspect(bytes) {
        case .serverName(let name, let ech):
            echPresent = ech
            return name == expectedHost ? .serverName(name, echPresent: ech) : .deny("sni_mismatch")
        case let result: return result
        }
    }
}
