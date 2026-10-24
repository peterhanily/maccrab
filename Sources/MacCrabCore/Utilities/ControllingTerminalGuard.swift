// ControllingTerminalGuard.swift
// MacCrabCore
//
// Gives the root engine a private controlling terminal at boot, so no open
// anywhere in the process can make a user's terminal its controlling tty.

import Darwin
import Foundation
import os.log

/// launchd starts the engine as a session leader with no controlling terminal,
/// and on Darwin such a process adopts the first tty it opens without
/// O_NOCTTY. Engine opens pass O_NOCTTY, but Security.framework opens the
/// paths it evaluates itself: a user who swaps an evaluated name onto their
/// own pty's slave would own the engine's terminal, and ^C on the master
/// would send it SIGINT. A session never replaces its controlling terminal,
/// so holding a private one closes that for every open in the process.
public enum ControllingTerminalGuard {
    public enum Outcome: Equatable, Sendable {
        /// Not a session leader, so no open can adopt a terminal.
        case notSessionLeader
        /// The session already has a controlling terminal (a shell or sudo
        /// started the process, or an earlier claim).
        case alreadyHasTerminal
        /// A private pty is now the session's controlling terminal.
        case claimed(slave: String)
        /// The claim failed; engine opens still pass O_NOCTTY.
        case failed(String)
        /// After a failed claim, the session gained a controlling terminal
        /// the engine never opened: a user's tty was adopted. A session never
        /// replaces its terminal, so this lasts the engine's lifetime. Only
        /// ^C, ^Z and ^\ from that tty are ignored: whoever holds its master
        /// can still send the engine SIGSTOP, SIGKILL or SIGTERM with TIOCSIG.
        case adopted
    }

    private struct Terminal: Sendable {
        let master: Int32
        let slave: Int32
    }

    /// Both ends stay open for the process lifetime: closing the master would
    /// hang the terminal up.
    private static let held = OSAllocatedUnfairLock<Terminal?>(initialState: nil)
    /// The latest claim's outcome; nil before the first.
    private static let latest = OSAllocatedUnfairLock<Outcome?>(initialState: nil)
    private static let logger = Logger(subsystem: "com.maccrab", category: "controlling-terminal")

    /// True once this process holds its private terminal.
    static var holdsTerminal: Bool { held.withLock { $0 != nil } }

    /// True while the latest claim failed, or once a user's tty was adopted.
    /// ^C, ^Z or ^\ on that tty must not stop the engine.
    public static var ignoresTerminalInterrupts: Bool { ignoresTerminalInterrupts(after: latest.withLock { $0 }) }

    static func ignoresTerminalInterrupts(after outcome: Outcome?) -> Bool {
        switch outcome {
        case .failed?, .adopted?: return true
        default: return false
        }
    }

    /// The state after `attempt`, given the state before it. Once a claim has
    /// failed only a claim clears that: a later probe that finds a terminal
    /// found one the engine never opened, a user's tty the session adopted.
    static func outcome(after previous: Outcome?, attempt: Outcome) -> Outcome {
        switch previous {
        case .failed?, .adopted?:
            switch attempt {
            case .claimed: return attempt
            case .alreadyHasTerminal: return .adopted
            default: return previous ?? attempt
            }
        default:
            return attempt
        }
    }

    /// The latest outcome, for the heartbeat.
    public static var status: String {
        switch latest.withLock({ $0 }) {
        case nil: return "not_attempted"
        case .notSessionLeader?: return "not_session_leader"
        case .alreadyHasTerminal?: return "already_had_terminal"
        case .claimed?: return "claimed"
        case .failed?: return "failed"
        case .adopted?: return "adopted"
        }
    }

    /// Claim a private pty as the controlling terminal, only when this process
    /// leads a session that has none. Anything else is left exactly as it is.
    @discardableResult
    public static func claimPrivateTerminalIfSessionLeader() -> Outcome {
        let outcome = attemptClaim()
        switch outcome {
        case .claimed(let slave):
            logger.notice("Holding a private controlling terminal (\(slave, privacy: .public)); no open can adopt another")
        case .failed(let reason):
            logger.warning("Could not claim a private controlling terminal (\(reason, privacy: .public)); engine opens still pass O_NOCTTY, and SIGINT, SIGQUIT and SIGTSTP are ignored until a retry succeeds")
        case .notSessionLeader, .alreadyHasTerminal, .adopted:
            break
        }
        return outcome
    }

    /// Claims again after a failed claim; the liveness heartbeat calls this.
    /// One user can hold every pty while the engine starts, so a failure must
    /// not last the engine's lifetime. Quiet unless it succeeds.
    public static func retryClaimAfterFailure() {
        guard case .failed? = latest.withLock({ $0 }), !holdsTerminal else { return }
        switch attemptClaim() {
        case .claimed(let slave):
            logger.notice("Holding a private controlling terminal (\(slave, privacy: .public)) after an earlier failed claim")
        case .adopted:
            logger.warning("The engine's session has a controlling terminal it never opened, so a user's tty was adopted after the failed claim; SIGINT, SIGQUIT and SIGTSTP stay ignored")
        default:
            break
        }
    }

    private static func attemptClaim() -> Outcome {
        let attempt = held.withLock { terminal -> Outcome in
            guard terminal == nil else { return .alreadyHasTerminal }
            let (outcome, claimed) = claim()
            terminal = claimed
            return outcome
        }
        let outcome = latest.withLock { previous -> Outcome in
            previous = Self.outcome(after: previous, attempt: attempt)
            return previous ?? attempt
        }
        if ignoresTerminalInterrupts(after: outcome) {
            // Without the claim a user's tty can still become the engine's
            // terminal: ^C would stop the engine, ^Z would suspend it and ^\
            // would kill it. None has any use here. SIGINT is ignored now, not
            // only once SignalHandlers installs its source, which keeps
            // ignoring it in the handler while this lasts.
            signal(SIGINT, SIG_IGN)
            signal(SIGTSTP, SIG_IGN)
            signal(SIGQUIT, SIG_IGN)
        }
        return outcome
    }

    private static func claim() -> (Outcome, Terminal?) {
        guard getsid(0) == getpid() else { return (.notSessionLeader, nil) }
        let probe = open("/dev/tty", O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC)
        if probe >= 0 {
            close(probe)
            return (.alreadyHasTerminal, nil)
        }
        let probeError = errno
        guard probeError == ENXIO || probeError == ENODEV else {
            return (.failed("/dev/tty errno \(probeError)"), nil)
        }

        let master = posix_openpt(O_RDWR | O_NOCTTY)
        guard master >= 0 else { return (.failed("posix_openpt errno \(errno)"), nil) }
        var slave: Int32 = -1
        func abandon(_ step: String) -> (Outcome, Terminal?) {
            let code = errno
            if slave >= 0 { close(slave) }
            close(master)
            return (.failed("\(step) errno \(code)"), nil)
        }
        guard fcntl(master, F_SETFD, FD_CLOEXEC) == 0,
              grantpt(master) == 0,
              unlockpt(master) == 0 else { return abandon("pty master") }
        var name = [CChar](repeating: 0, count: 128)
        guard ptsname_r(master, &name, name.count) == 0 else { return abandon("ptsname") }
        let slavePath = String(cString: name)
        slave = open(slavePath, O_RDWR | O_NOCTTY | O_CLOEXEC)
        guard slave >= 0 else { return abandon("open \(slavePath)") }

        // Set before the terminal is ours: no input can raise a signal, a
        // child's write to /dev/tty never stops it, and no hangup is sent.
        var attributes = termios()
        guard tcgetattr(slave, &attributes) == 0 else { return abandon("tcgetattr") }
        attributes.c_lflag &= ~tcflag_t(ISIG | ICANON | ECHO | IEXTEN | TOSTOP)
        attributes.c_cflag |= tcflag_t(CLOCAL)
        guard tcsetattr(slave, TCSANOW, &attributes) == 0 else { return abandon("tcsetattr") }
        guard ioctl(slave, TIOCSCTTY, 0) == 0 else { return abandon("TIOCSCTTY") }

        // From here the descriptors are kept whatever happens: closing the
        // master now would hang up the session's terminal.
        let terminal = Terminal(master: master, slave: slave)
        let drain = Thread {
            // Discard output so a writer to /dev/tty never blocks on a full
            // queue. Nothing ever writes to the master, so there is no input.
            var buffer = [UInt8](repeating: 0, count: 1_024)
            while true {
                let count = buffer.withUnsafeMutableBytes { read(master, $0.baseAddress, $0.count) }
                if count > 0 || (count < 0 && errno == EINTR) { continue }
                let code = count < 0 ? errno : 0
                logger.warning("The private terminal's drain stopped (read returned \(count, privacy: .public), errno \(code, privacy: .public)); a writer to /dev/tty may now block")
                return
            }
        }
        drain.name = "com.maccrab.controlling-terminal.drain"
        drain.qualityOfService = .background
        drain.start()

        // /dev/tty is its own device node, so check the session, not st_rdev.
        let check = open("/dev/tty", O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC)
        if check >= 0 { close(check) }
        guard check >= 0, tcgetsid(slave) == getpid() else {
            return (.failed("\(slavePath) is not the session's terminal after TIOCSCTTY"), terminal)
        }
        return (.claimed(slave: slavePath), terminal)
    }
}
