#include "include/keri_windows/keri_windows_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "keri_windows_plugin.h"

void KeriWindowsPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  keri_windows::KeriWindowsPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
