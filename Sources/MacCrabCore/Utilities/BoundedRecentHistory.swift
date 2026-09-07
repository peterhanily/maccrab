/// Fixed-capacity FIFO retention for diagnostic history. Reaching capacity
/// forgets the oldest retained value; callers must keep policy and lifetime
/// outcome counters separately. A zero capacity retains no values.
struct BoundedRecentHistory<Element: Sendable>: Sendable {
    let capacity: Int
    private var storage: [Element?]
    private var head = 0
    private(set) var count = 0

    init(capacity: Int) {
        self.capacity = max(0, capacity)
        storage = Array(repeating: nil, count: max(0, capacity))
    }

    /// Retained values, oldest first. The returned snapshot is also bounded.
    var elements: [Element] {
        (0..<count).compactMap { storage[(head + $0) % capacity] }
    }

    /// Returns the forgotten value, if any (the input when capacity is zero).
    @discardableResult
    mutating func append(_ element: Element) -> Element? {
        guard capacity > 0 else { return element }
        if count < capacity {
            storage[(head + count) % capacity] = element
            count += 1
            return nil
        }
        let forgotten = storage[head]
        storage[head] = element
        head = (head + 1) % capacity
        return forgotten
    }
}

/// Recent deduplication only, never an allow/block policy. Repeated observations
/// do not refresh FIFO order. A forgotten key is new to this history and may
/// produce another alert if it is observed again; detection remains enabled.
struct BoundedRecentSet<Element: Hashable & Sendable>: Sendable {
    private var history: BoundedRecentHistory<Element>
    private var members: Set<Element> = []

    init(capacity: Int) { history = BoundedRecentHistory(capacity: capacity) }

    var count: Int { members.count }
    func contains(_ element: Element) -> Bool { members.contains(element) }

    /// True when this observation was absent from the retained dedup window.
    @discardableResult
    mutating func insert(_ element: Element) -> Bool {
        guard members.insert(element).inserted else { return false }
        if let forgotten = history.append(element) { members.remove(forgotten) }
        return true
    }

    /// Reconcile against a successfully observed current inventory. Callers
    /// must not pass a fabricated empty inventory after an enumeration failure.
    mutating func retain(where shouldKeep: (Element) -> Bool) {
        let kept = history.elements.filter(shouldKeep)
        history = BoundedRecentHistory(capacity: history.capacity)
        members.removeAll(keepingCapacity: true)
        for element in kept { insert(element) }
    }
}
