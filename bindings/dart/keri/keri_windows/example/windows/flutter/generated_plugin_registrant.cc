//
//  Generated file. Do not edit.
//

// clang-format off

#include "generated_plugin_registrant.h"

#include <asymmetric_crypto_primitives/asymmetric_crypto_primitives_plugin_c_api.h>
#include <keri_windows/keri_windows_plugin_c_api.h>
#include <local_auth_windows/local_auth_plugin.h>
#include <nacl_win/nacl_win_plugin_c_api.h>

void RegisterPlugins(flutter::PluginRegistry* registry) {
  AsymmetricCryptoPrimitivesPluginCApiRegisterWithRegistrar(
      registry->GetRegistrarForPlugin("AsymmetricCryptoPrimitivesPluginCApi"));
  KeriWindowsPluginCApiRegisterWithRegistrar(
      registry->GetRegistrarForPlugin("KeriWindowsPluginCApi"));
  LocalAuthPluginRegisterWithRegistrar(
      registry->GetRegistrarForPlugin("LocalAuthPlugin"));
  NaclWinPluginCApiRegisterWithRegistrar(
      registry->GetRegistrarForPlugin("NaclWinPluginCApi"));
}
