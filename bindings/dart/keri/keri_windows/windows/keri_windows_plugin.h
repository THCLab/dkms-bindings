#ifndef FLUTTER_PLUGIN_KERI_WINDOWS_PLUGIN_H_
#define FLUTTER_PLUGIN_KERI_WINDOWS_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace keri_windows {

class KeriWindowsPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  KeriWindowsPlugin();

  virtual ~KeriWindowsPlugin();

  // Disallow copy and assign.
  KeriWindowsPlugin(const KeriWindowsPlugin&) = delete;
  KeriWindowsPlugin& operator=(const KeriWindowsPlugin&) = delete;

 private:
  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace keri_windows

#endif  // FLUTTER_PLUGIN_KERI_WINDOWS_PLUGIN_H_
