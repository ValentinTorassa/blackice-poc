import Foundation

enum ConfigurationError: Error, CustomStringConvertible {
    case invalid(String)
    var description: String {
        switch self { case .invalid(let message): return message }
    }
}

/// Foundation validates syntax; this additional pass rejects duplicate keys,
/// including escaped aliases, before JSONDecoder can silently pick one value.
enum StrictJSON {
    static let maximumBytes = 1_048_576

    static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        guard !data.isEmpty, data.count <= maximumBytes else {
            throw ConfigurationError.invalid("configuration_size")
        }
        var scanner = KeyScanner(bytes: Array(data))
        try scanner.value(depth: 0)
        scanner.whitespace()
        guard scanner.index == scanner.bytes.count else {
            throw ConfigurationError.invalid("invalid_json")
        }
        return try JSONDecoder().decode(type, from: data)
    }

    private struct KeyScanner {
        let bytes: [UInt8]
        var index = 0

        mutating func whitespace() {
            while index < bytes.count, [9, 10, 13, 32].contains(bytes[index]) { index += 1 }
        }

        mutating func take(_ byte: UInt8) throws {
            whitespace()
            guard index < bytes.count, bytes[index] == byte else {
                throw ConfigurationError.invalid("invalid_json")
            }
            index += 1
        }

        mutating func string() throws -> String {
            whitespace()
            let start = index
            try take(34)
            while index < bytes.count {
                let byte = bytes[index]
                index += 1
                if byte == 34 {
                    return try JSONDecoder().decode(String.self, from: Data(bytes[start..<index]))
                }
                if byte == 92 { index += 1 }
            }
            throw ConfigurationError.invalid("invalid_json_string")
        }

        mutating func value(depth: Int) throws {
            guard depth < 32 else { throw ConfigurationError.invalid("json_nesting_limit") }
            whitespace()
            guard index < bytes.count else { throw ConfigurationError.invalid("invalid_json") }
            switch bytes[index] {
            case 123: // object
                index += 1
                whitespace()
                if index < bytes.count, bytes[index] == 125 { index += 1; return }
                var keys = Set<String>()
                while true {
                    let key = try string()
                    guard keys.insert(key).inserted else {
                        throw ConfigurationError.invalid("duplicate_json_key")
                    }
                    try take(58)
                    try value(depth: depth + 1)
                    whitespace()
                    if index < bytes.count, bytes[index] == 125 { index += 1; return }
                    try take(44)
                }
            case 91: // array
                index += 1
                whitespace()
                if index < bytes.count, bytes[index] == 93 { index += 1; return }
                while true {
                    try value(depth: depth + 1)
                    whitespace()
                    if index < bytes.count, bytes[index] == 93 { index += 1; return }
                    try take(44)
                }
            case 34: _ = try string()
            default:
                let start = index
                while index < bytes.count, ![9, 10, 13, 32, 44, 93, 125].contains(bytes[index]) {
                    index += 1
                }
                guard start != index else { throw ConfigurationError.invalid("invalid_json") }
                // Syntax and scalar types are checked by JSONDecoder below.
            }
        }
    }
}

private struct AnyKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

extension Decoder {
    func rejectUnknownKeys(_ allowed: Set<String>) throws {
        let container = try container(keyedBy: AnyKey.self)
        guard Set(container.allKeys.map(\.stringValue)).isSubset(of: allowed) else {
            throw ConfigurationError.invalid("unknown_configuration_field")
        }
    }
}

extension KeyedDecodingContainer {
    /// Defaults are for omitted keys only. An explicit null is a configuration error.
    func decodeOrDefault<T: Decodable>(_ type: T.Type, forKey key: Key, default value: T) throws -> T {
        contains(key) ? try decode(type, forKey: key) : value
    }
}
