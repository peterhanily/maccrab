import Foundation
import Darwin
import MacCrabCore
import os.log

// Disable stdout buffering so output appears immediately in log files
setbuf(stdout, nil)

logger.info("MacCrab daemon starting...")

// 1. Initialize all components
let state = await DaemonSetup.initialize()

// 2. Print startup banner
await StartupBanner.print(state: state)

// 3. Install signal handlers (SIGHUP, SIGTERM, SIGINT)
let signalHandles = SignalHandlers.install(state: state)

// 4. Start background monitor tasks
MonitorTasks.start(state: state)

// 5. Start periodic timers
var eventCount: UInt64 = 0
var alertCount: UInt64 = 0
let startTime = Date()
let timerHandles = DaemonTimers.start(
    state: state,
    eventCount: { eventCount },
    alertCount: { alertCount },
    startTime: startTime
)

// 6. Merge event sources and run the main event processing loop
let eventStream = state.mergedEventStream()
await EventLoop.run(
    state: state,
    eventStream: eventStream,
    eventCount: &eventCount,
    alertCount: &alertCount
)

// Keep handles alive (prevents ARC from deallocating dispatch sources)
_ = signalHandles
_ = timerHandles
