#ifndef FLUTTER_PLUGIN_KERI_PLUGIN_H_
#define FLUTTER_PLUGIN_KERI_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace keri {

class KeriPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  KeriPlugin();

  virtual ~KeriPlugin();

  // Disallow copy and assign.
  KeriPlugin(const KeriPlugin&) = delete;
  KeriPlugin& operator=(const KeriPlugin&) = delete;

 private:
  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace keri

#endif  // FLUTTER_PLUGIN_KERI_PLUGIN_H_
