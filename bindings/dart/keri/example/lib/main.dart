import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:keri/bridge_generated.dart';
import 'package:keri/keri.dart';
import 'package:path_provider/path_provider.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _platformVersion = 'Unknown';
  final _keriPlugin = Keri();

  @override
  void initState() {
    initKel();
    super.initState();
  }

  Future<void> initKel()async {
    var dir = await getLocalPath();
    var conf = Config(initialOobis: "[{\"eid\":\"BKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ\",\"scheme\":\"http\",\"url\":\"http://127.0.0.1:3236/\"}]");
    print(conf);
    await Keri.initKel(inputAppDir: dir, optionalConfigs: conf);
    print('initialized');
  }


  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Center(
          child: Text('Running on: $_platformVersion\n'),
        ),
      ),
    );
  }

  Future<String> getLocalPath() async {
    final directory = await getApplicationDocumentsDirectory();
    return directory.path;
  }
}
