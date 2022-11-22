//
//  Generated file. Do not edit.
//

// clang-format off

#include "generated_plugin_registrant.h"

#include <keri_platform_interface/keri_platform_interface_plugin_c_api.h>
#include <keri_windows/keri_windows_plugin_c_api.h>

void RegisterPlugins(flutter::PluginRegistry* registry) {
  KeriPlatformInterfacePluginCApiRegisterWithRegistrar(
      registry->GetRegistrarForPlugin("KeriPlatformInterfacePluginCApi"));
  KeriWindowsPluginCApiRegisterWithRegistrar(
      registry->GetRegistrarForPlugin("KeriWindowsPluginCApi"));
}
