import 'package:flutter_test/flutter_test.dart';
import 'package:keri/keri.dart';

void main(){
  test('The kel fails to init as there is no such directory', () async{


    await Keri.initKel(inputAppDir: 'cat');
    expect(() => Keri.initKel(inputAppDir: 'cat'), throwsException);
  });
}