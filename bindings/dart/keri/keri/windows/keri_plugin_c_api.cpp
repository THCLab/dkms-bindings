#include "include/keri/keri_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "keri_plugin.h"

void KeriPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  keri::KeriPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
