import Flutter
import UIKit

public class SwiftKeriPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "keri", binaryMessenger: registrar.messenger())
    let instance = SwiftKeriPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    result("iOS " + UIDevice.current.systemVersion)
  }

  public func dummyMethodToEnforceBundling() {
     // This will never be executed
    dummy_method_to_enforce_bundling();
  }
}
