#import "DartPlugin.h"
#if __has_include(<keri/keri-Swift.h>)
#import <keri/keri-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "keri-Swift.h"
#endif

@implementation DartPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftDartPlugin registerWithRegistrar:registrar];
}
@end