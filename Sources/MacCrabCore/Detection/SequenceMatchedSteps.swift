/// The binding owns its exact step identity; the inline case need not allocate
/// an extra dictionary key slot or a one-entry Dictionary. Other fields stay intact.
protocol SequenceStepBinding: Sendable, Equatable {
    var stepId: String { get }
}

/// Value-semantic storage for the common one-bound-step partial. Additional
/// bindings use the existing Dictionary representation and lookup semantics.
/// Iteration uses small value iterators, never an intermediate Array/Dictionary.
struct SequenceMatchedSteps<Binding: SequenceStepBinding>: Sendable, Equatable,
    ExpressibleByDictionaryLiteral, Sequence {
    private enum Storage: Sendable, Equatable {
        case empty
        case single(Binding)
        case multiple([String: Binding])
    }

    private var storage: Storage = .empty

    init() {}

    init<S: Sequence>(uniqueKeysWithValues elements: S) where S.Element == (String, Binding) {
        for (key, value) in elements {
            precondition(self[key] == nil, "Duplicate sequence binding identity")
            self[key] = value
        }
    }

    init(dictionaryLiteral elements: (String, Binding)...) {
        self.init(uniqueKeysWithValues: elements)
    }

    var count: Int {
        switch storage {
        case .empty: return 0
        case .single: return 1
        case .multiple(let bindings): return bindings.count
        }
    }

    var isEmpty: Bool { count == 0 }

    /// Structural diagnostics only: this does not estimate String/Array heap
    /// storage, allocator retention or the process's physical footprint.
    var isInlineSingle: Bool {
        if case .single = storage { return true }
        return false
    }

    var isDictionaryBacked: Bool {
        if case .multiple = storage { return true }
        return false
    }

    subscript(key: String) -> Binding? {
        get {
            switch storage {
            case .empty: return nil
            case .single(let binding): return binding.stepId == key ? binding : nil
            case .multiple(let bindings): return bindings[key]
            }
        }
        set {
            if let newValue {
                precondition(newValue.stepId == key, "Sequence binding key disagrees with its identity")
            }
            switch storage {
            case .empty:
                if let newValue { storage = .single(newValue) }
            case .single(let binding):
                if binding.stepId == key {
                    storage = newValue.map(Storage.single) ?? .empty
                } else if let newValue {
                    storage = .multiple([binding.stepId: binding, key: newValue])
                }
            case .multiple(var bindings):
                // Release this container's old reference before mutating the
                // extracted dictionary. Other value copies still correctly
                // force COW; the extraction itself must not force a copy.
                storage = .empty
                bindings[key] = newValue
                if bindings.isEmpty {
                    storage = .empty
                } else if bindings.count == 1, let binding = bindings.first?.value {
                    storage = .single(binding)
                } else {
                    storage = .multiple(bindings)
                }
            }
        }
    }

    struct Iterator: IteratorProtocol {
        private var single: Binding?
        private var multiple: Dictionary<String, Binding>.Iterator?

        fileprivate init(single: Binding?, multiple: Dictionary<String, Binding>.Iterator?) {
            self.single = single
            self.multiple = multiple
        }

        mutating func next() -> (key: String, value: Binding)? {
            if let binding = single {
                single = nil
                return (binding.stepId, binding)
            }
            guard var iterator = multiple else { return nil }
            let element = iterator.next()
            multiple = iterator
            return element
        }
    }

    func makeIterator() -> Iterator {
        switch storage {
        case .empty: return Iterator(single: nil, multiple: nil)
        case .single(let binding): return Iterator(single: binding, multiple: nil)
        case .multiple(let bindings): return Iterator(single: nil, multiple: bindings.makeIterator())
        }
    }

    struct Keys: Sequence {
        fileprivate let bindings: SequenceMatchedSteps
        struct Iterator: IteratorProtocol {
            fileprivate var base: SequenceMatchedSteps.Iterator
            mutating func next() -> String? { base.next()?.key }
        }
        func makeIterator() -> Iterator { Iterator(base: bindings.makeIterator()) }
    }

    struct Values: Sequence {
        fileprivate let bindings: SequenceMatchedSteps
        struct Iterator: IteratorProtocol {
            fileprivate var base: SequenceMatchedSteps.Iterator
            mutating func next() -> Binding? { base.next()?.value }
        }
        func makeIterator() -> Iterator { Iterator(base: bindings.makeIterator()) }
    }

    var keys: Keys { Keys(bindings: self) }
    var values: Values { Values(bindings: self) }
}
