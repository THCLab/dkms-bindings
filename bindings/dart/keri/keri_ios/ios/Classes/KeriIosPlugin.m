#import "KeriIosPlugin.h"
#if __has_include(<keri_ios/keri_ios-Swift.h>)
#import <keri_ios/keri_ios-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "keri_ios-Swift.h"
#endif

@implementation KeriIosPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftKeriIosPlugin registerWithRegistrar:registrar];
}
@end
