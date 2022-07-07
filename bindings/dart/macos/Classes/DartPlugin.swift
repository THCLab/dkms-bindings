import Cocoa
import FlutterMacOS

public class SwiftDartPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "dart", binaryMessenger: registrar.messenger)
    let instance = SwiftDartPlugin()
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
