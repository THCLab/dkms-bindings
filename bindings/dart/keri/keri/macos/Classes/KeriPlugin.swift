import Cocoa
import FlutterMacOS

public class KeriPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "keri", binaryMessenger: registrar.messenger)
    let instance = KeriPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "getPlatformVersion":
      result("macOS " + ProcessInfo.processInfo.operatingSystemVersionString)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  public func dummyMethodToEnforceBundling() {
    // This will never be executed
    dummy_method_to_enforce_bundling()
  }
}
