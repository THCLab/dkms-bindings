library keri_android;

import 'package:keri_platform_interface/keri_platform_interface.dart';

export 'package:keri_platform_interface/keri_platform_interface.dart';

class KeriAndroid {
  static void registerWith() {
    // Plugin registration is currently a no-op:
    // FRB v2 loads libdartkeriox.so directly via RustLib.init().
    // Host key-provider callbacks (Step 8) will be wired here later.
  }

  static Future<void> init() => RustLib.init();
}
