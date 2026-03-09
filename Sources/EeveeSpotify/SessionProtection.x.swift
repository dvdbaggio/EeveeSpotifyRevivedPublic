import Orion
import Foundation

// MARK: - Session Logout Protection
// Hooks all logout-related methods to prevent Spotify from logging out
// when it detects the account isn't actually premium.
// Also intercepts Ably WebSocket messages to block server-side revocation events.
// Additionally blocks network endpoints that trigger session invalidation.
// Extends OAuth token expiry to prevent internal reauth triggers.

struct SessionLogoutHookGroup: HookGroup { }

// MARK: - SPTAuthSessionImplementation — Core Session Hooks

class SPTAuthSessionHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "SPTAuthSessionImplementation"

    // orion:new
    static var allowLogout = false

    func logout() {
        if SPTAuthSessionHook.allowLogout {
            orig.logout()
        }
    }

    // The MAIN logout entry point — logoutWithReason: is what's actually called
    // when the session is detected as invalid/expired
    func logoutWithReason(_ reason: AnyObject) {
        if SPTAuthSessionHook.allowLogout {
            orig.logoutWithReason(reason)
        }
    }

    // Block the delegate notification that triggers downstream logout cascade
    func callSessionDidLogoutOnDelegateWithReason(_ reason: AnyObject) {
        if SPTAuthSessionHook.allowLogout {
            orig.callSessionDidLogoutOnDelegateWithReason(reason)
        }
    }

    // Block analytics logging for logout events
    func logWillLogoutEventWithLogoutReason(_ reason: AnyObject) {
        if SPTAuthSessionHook.allowLogout {
            orig.logWillLogoutEventWithLogoutReason(reason)
        }
    }

    func destroy() {
        if SPTAuthSessionHook.allowLogout {
            orig.destroy()
        } else {
            writeDebugLog("Blocked session destroy")
        }
    }

    func productStateUpdated(_ state: AnyObject) {
        orig.productStateUpdated(state)
    }

    func tryReconnect(_ arg1: AnyObject, toAP arg2: AnyObject) {
        orig.tryReconnect(arg1, toAP: arg2)
    }
}

// MARK: - SessionServiceImpl (Connectivity_SessionImpl module)

class SessionServiceImplHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "_TtC24Connectivity_SessionImpl18SessionServiceImpl"

    func automatedLogoutThenLogin() {
    }

    func userInitiatedLogout() {
        // The C++ timer calls this via Swift vtable dispatch, NOT from the main thread.
        // Real user taps go through the main thread. Only allow if on main thread.
        if Thread.isMainThread {
            SPTAuthSessionHook.allowLogout = true
            orig.userInitiatedLogout()
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                SPTAuthSessionHook.allowLogout = false
            }
        }
    }

    func sessionDidLogout(_ session: AnyObject, withReason reason: AnyObject) {
        if SPTAuthSessionHook.allowLogout {
            orig.sessionDidLogout(session, withReason: reason)
        }
    }
}

// MARK: - SPTAuthLegacyLoginControllerImplementation

class LegacyLoginControllerHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "SPTAuthLegacyLoginControllerImplementation"

    func sessionDidLogout(_ session: AnyObject, withReason reason: AnyObject) {
        if SPTAuthSessionHook.allowLogout {
            orig.sessionDidLogout(session, withReason: reason)
        }
    }

    func destroySession() {
        if SPTAuthSessionHook.allowLogout {
            orig.destroySession()
        }
    }

    func forgetStoredCredentials() {
        if SPTAuthSessionHook.allowLogout {
            orig.forgetStoredCredentials()
        }
    }

    func invalidate() {
        if SPTAuthSessionHook.allowLogout {
            orig.invalidate()
        }
    }
}

// MARK: - OauthAccessTokenBridge — Extend token expiry
// This private class inside Connectivity_SessionImpl controls the OAuth token's
// expiry time. By hooking expiresAt to return a far-future date, we prevent
// the internal timer from marking the token as expired.

class OauthAccessTokenBridgeHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "_TtC24Connectivity_SessionImplP33_831B98CC28223E431E21CD27ADD20AF222OauthAccessTokenBridge"

    // Hook the GETTER
    func expiresAt() -> Any {
        let farFuture = Date(timeIntervalSinceNow: 365 * 24 * 60 * 60)
        return farFuture
    }

    func setExpiresAt(_ date: Any) {
        let farFuture = Date(timeIntervalSinceNow: 365 * 24 * 60 * 60)
        orig.setExpiresAt(farFuture)
    }

    // Hook init to directly modify the ivar using ObjC runtime
    // This catches cases where C++ sets the ivar without going through the ObjC setter
    func `init`() -> NSObject? {
        let result = orig.`init`()
        extendExpiryIvar()
        // Also start a repeating timer to keep extending the ivar
        startExpiryExtender()
        return result
    }

    // orion:new
    func extendExpiryIvar() {
        let bridgeClass: AnyClass = type(of: target)
        if let ivar = class_getInstanceVariable(bridgeClass, "expiresAt") {
            let farFuture = Date(timeIntervalSinceNow: 365 * 24 * 60 * 60)
            object_setIvar(target, ivar, farFuture)
        }
    }

    // orion:new
    func startExpiryExtender() {
        let weak = target
        // Extend the ivar every 60 seconds
        DispatchQueue.global(qos: .utility).async {
            while true {
                Thread.sleep(forTimeInterval: 60)
                guard let obj = weak as? NSObject else { break }
                let cls: AnyClass = type(of: obj)
                if let ivar = class_getInstanceVariable(cls, "expiresAt") {
                    let farFuture = Date(timeIntervalSinceNow: 365 * 24 * 60 * 60)
                    object_setIvar(obj, ivar, farFuture)
                }
            }
        }
    }
}



// NOTE: ColdStartupTimeKeeperImplementation is a pure Swift class (not NSObject).
// Cannot hook it with Orion — crashes with targetHasIncompatibleType.
// NOTE: executeBlockRunner on SPTAsyncNativeTimerManagerThreadImpl is too broad —
// blocking it kills ALL timers including playback advancement.

// MARK: - Ably WebSocket Transport Hooks
// Intercepts Ably real-time messages to block server-side logout/revocation events

// Blocked Ably protocol actions:
// 5=disconnect, 6=disconnected, 7=close, 8=closed, 9=error, 12=detach, 13=detached, 17=auth
private let blockedAblyActions: Set<Int> = [5, 6, 7, 8, 9, 12, 13, 17]

private func extractAblyAction(_ text: String) -> Int? {
    guard let range = text.range(of: "\"action\":") else { return nil }
    let afterAction = text[range.upperBound...]
    let digits = afterAction.prefix(while: { $0.isNumber })
    return Int(digits)
}

class ARTWebSocketTransportHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "ARTWebSocketTransport"

    func webSocket(_ ws: AnyObject, didReceiveMessage message: AnyObject) {
        if let msgString = message as? String {
            if let action = extractAblyAction(msgString) {
                if blockedAblyActions.contains(action) {
                    return
                }
            }
        }
        orig.webSocket(ws, didReceiveMessage: message)
    }

    func webSocket(_ ws: AnyObject, didFailWithError error: AnyObject) {
    }
}

// MARK: - Ably SRWebSocket Frame Hook

class ARTSRWebSocketHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "ARTSRWebSocket"

    func _handleFrameWithData(_ data: NSData, opCode code: Int) {
        if code == 1,
           let text = String(data: data as Data, encoding: .utf8) {
            if let action = extractAblyAction(text) {
                if blockedAblyActions.contains(action) {
                    return
                }
            }
        }
        orig._handleFrameWithData(data, opCode: code)
    }
}

// MARK: - Global URLSessionTask hook to catch auth traffic bypassing SPTDataLoaderService

class URLSessionTaskResumeHook: ClassHook<NSObject> {
    typealias Group = SessionLogoutHookGroup
    static let targetName = "NSURLSessionTask"

    func resume() {
        if let task = target as? URLSessionTask,
           let url = task.currentRequest?.url ?? task.originalRequest?.url,
           let host = url.host?.lowercased() {

            let elapsed = Date().timeIntervalSince(tweakInitTime)
            let path = url.path

            // After initial startup (30s), block login5 re-auth requests.
            if elapsed > 30 {
                if host.contains("login5") {
                    writeDebugLog("Blocked login5 re-auth at \(Int(elapsed))s")
                    return
                }
                // Block Google OAuth token refresh (feeds into login5 v4)
                if host.contains("googleapis.com") && path.contains("/token") {
                    writeDebugLog("Blocked Google OAuth refresh at \(Int(elapsed))s")
                    return
                }
            }

            // Block outgoing DeleteToken/signup requests at network level
            if host.contains("spotify") || host.contains("spclient") {
                if path.contains("DeleteToken") {
                    return
                }
                if path.contains("signup/public") {
                    return
                }
                if path.contains("pses/screenconfig") {
                    return
                }
                // Block bootstrap re-fetch after initial startup
                if elapsed > 30 && path.contains("bootstrap/v1/bootstrap") {
                    writeDebugLog("Blocked bootstrap re-fetch at \(Int(elapsed))s")
                    return
                }
                // Block apresolve after initial startup (precedes reinit)
                if elapsed > 30 && host.contains("apresolve") {
                    writeDebugLog("Blocked apresolve at \(Int(elapsed))s")
                    return
                }
            }
        }
        orig.resume()
    }
}


