// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target

part of 'bridge_generated.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

T _$identity<T>(T value) => value;

final _privateConstructorUsedError = UnsupportedError(
    'It seems like you constructed your class using `MyClass._()`. This constructor is only meant to be used by freezed and you are not supposed to need it nor use it.\nPlease check the documentation here for more information: https://github.com/rrousselGit/freezed#custom-getters-and-methods');

/// @nodoc
mixin _$Identifier {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(PublicKey field0) basic,
    required TResult Function(Digest field0) selfAddressing,
    required TResult Function(Signature field0) selfSigning,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function(PublicKey field0)? basic,
    TResult Function(Digest field0)? selfAddressing,
    TResult Function(Signature field0)? selfSigning,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(PublicKey field0)? basic,
    TResult Function(Digest field0)? selfAddressing,
    TResult Function(Signature field0)? selfSigning,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Identifier_Basic value) basic,
    required TResult Function(Identifier_SelfAddressing value) selfAddressing,
    required TResult Function(Identifier_SelfSigning value) selfSigning,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(Identifier_Basic value)? basic,
    TResult Function(Identifier_SelfAddressing value)? selfAddressing,
    TResult Function(Identifier_SelfSigning value)? selfSigning,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Identifier_Basic value)? basic,
    TResult Function(Identifier_SelfAddressing value)? selfAddressing,
    TResult Function(Identifier_SelfSigning value)? selfSigning,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $IdentifierCopyWith<$Res> {
  factory $IdentifierCopyWith(
          Identifier value, $Res Function(Identifier) then) =
      _$IdentifierCopyWithImpl<$Res>;
}

/// @nodoc
class _$IdentifierCopyWithImpl<$Res> implements $IdentifierCopyWith<$Res> {
  _$IdentifierCopyWithImpl(this._value, this._then);

  final Identifier _value;
  // ignore: unused_field
  final $Res Function(Identifier) _then;
}

/// @nodoc
abstract class _$$Identifier_BasicCopyWith<$Res> {
  factory _$$Identifier_BasicCopyWith(
          _$Identifier_Basic value, $Res Function(_$Identifier_Basic) then) =
      __$$Identifier_BasicCopyWithImpl<$Res>;
  $Res call({PublicKey field0});
}

/// @nodoc
class __$$Identifier_BasicCopyWithImpl<$Res>
    extends _$IdentifierCopyWithImpl<$Res>
    implements _$$Identifier_BasicCopyWith<$Res> {
  __$$Identifier_BasicCopyWithImpl(
      _$Identifier_Basic _value, $Res Function(_$Identifier_Basic) _then)
      : super(_value, (v) => _then(v as _$Identifier_Basic));

  @override
  _$Identifier_Basic get _value => super._value as _$Identifier_Basic;

  @override
  $Res call({
    Object? field0 = freezed,
  }) {
    return _then(_$Identifier_Basic(
      field0 == freezed
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as PublicKey,
    ));
  }
}

/// @nodoc

class _$Identifier_Basic implements Identifier_Basic {
  const _$Identifier_Basic(this.field0);

  @override
  final PublicKey field0;

  @override
  String toString() {
    return 'Identifier.basic(field0: $field0)';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$Identifier_Basic &&
            const DeepCollectionEquality().equals(other.field0, field0));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(field0));

  @JsonKey(ignore: true)
  @override
  _$$Identifier_BasicCopyWith<_$Identifier_Basic> get copyWith =>
      __$$Identifier_BasicCopyWithImpl<_$Identifier_Basic>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(PublicKey field0) basic,
    required TResult Function(Digest field0) selfAddressing,
    required TResult Function(Signature field0) selfSigning,
  }) {
    return basic(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function(PublicKey field0)? basic,
    TResult Function(Digest field0)? selfAddressing,
    TResult Function(Signature field0)? selfSigning,
  }) {
    return basic?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(PublicKey field0)? basic,
    TResult Function(Digest field0)? selfAddressing,
    TResult Function(Signature field0)? selfSigning,
    required TResult orElse(),
  }) {
    if (basic != null) {
      return basic(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Identifier_Basic value) basic,
    required TResult Function(Identifier_SelfAddressing value) selfAddressing,
    required TResult Function(Identifier_SelfSigning value) selfSigning,
  }) {
    return basic(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(Identifier_Basic value)? basic,
    TResult Function(Identifier_SelfAddressing value)? selfAddressing,
    TResult Function(Identifier_SelfSigning value)? selfSigning,
  }) {
    return basic?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Identifier_Basic value)? basic,
    TResult Function(Identifier_SelfAddressing value)? selfAddressing,
    TResult Function(Identifier_SelfSigning value)? selfSigning,
    required TResult orElse(),
  }) {
    if (basic != null) {
      return basic(this);
    }
    return orElse();
  }
}

abstract class Identifier_Basic implements Identifier {
  const factory Identifier_Basic(final PublicKey field0) = _$Identifier_Basic;

  PublicKey get field0;
  @JsonKey(ignore: true)
  _$$Identifier_BasicCopyWith<_$Identifier_Basic> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$Identifier_SelfAddressingCopyWith<$Res> {
  factory _$$Identifier_SelfAddressingCopyWith(
          _$Identifier_SelfAddressing value,
          $Res Function(_$Identifier_SelfAddressing) then) =
      __$$Identifier_SelfAddressingCopyWithImpl<$Res>;
  $Res call({Digest field0});
}

/// @nodoc
class __$$Identifier_SelfAddressingCopyWithImpl<$Res>
    extends _$IdentifierCopyWithImpl<$Res>
    implements _$$Identifier_SelfAddressingCopyWith<$Res> {
  __$$Identifier_SelfAddressingCopyWithImpl(_$Identifier_SelfAddressing _value,
      $Res Function(_$Identifier_SelfAddressing) _then)
      : super(_value, (v) => _then(v as _$Identifier_SelfAddressing));

  @override
  _$Identifier_SelfAddressing get _value =>
      super._value as _$Identifier_SelfAddressing;

  @override
  $Res call({
    Object? field0 = freezed,
  }) {
    return _then(_$Identifier_SelfAddressing(
      field0 == freezed
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as Digest,
    ));
  }
}

/// @nodoc

class _$Identifier_SelfAddressing implements Identifier_SelfAddressing {
  const _$Identifier_SelfAddressing(this.field0);

  @override
  final Digest field0;

  @override
  String toString() {
    return 'Identifier.selfAddressing(field0: $field0)';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$Identifier_SelfAddressing &&
            const DeepCollectionEquality().equals(other.field0, field0));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(field0));

  @JsonKey(ignore: true)
  @override
  _$$Identifier_SelfAddressingCopyWith<_$Identifier_SelfAddressing>
      get copyWith => __$$Identifier_SelfAddressingCopyWithImpl<
          _$Identifier_SelfAddressing>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(PublicKey field0) basic,
    required TResult Function(Digest field0) selfAddressing,
    required TResult Function(Signature field0) selfSigning,
  }) {
    return selfAddressing(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function(PublicKey field0)? basic,
    TResult Function(Digest field0)? selfAddressing,
    TResult Function(Signature field0)? selfSigning,
  }) {
    return selfAddressing?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(PublicKey field0)? basic,
    TResult Function(Digest field0)? selfAddressing,
    TResult Function(Signature field0)? selfSigning,
    required TResult orElse(),
  }) {
    if (selfAddressing != null) {
      return selfAddressing(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Identifier_Basic value) basic,
    required TResult Function(Identifier_SelfAddressing value) selfAddressing,
    required TResult Function(Identifier_SelfSigning value) selfSigning,
  }) {
    return selfAddressing(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(Identifier_Basic value)? basic,
    TResult Function(Identifier_SelfAddressing value)? selfAddressing,
    TResult Function(Identifier_SelfSigning value)? selfSigning,
  }) {
    return selfAddressing?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Identifier_Basic value)? basic,
    TResult Function(Identifier_SelfAddressing value)? selfAddressing,
    TResult Function(Identifier_SelfSigning value)? selfSigning,
    required TResult orElse(),
  }) {
    if (selfAddressing != null) {
      return selfAddressing(this);
    }
    return orElse();
  }
}

abstract class Identifier_SelfAddressing implements Identifier {
  const factory Identifier_SelfAddressing(final Digest field0) =
      _$Identifier_SelfAddressing;

  Digest get field0;
  @JsonKey(ignore: true)
  _$$Identifier_SelfAddressingCopyWith<_$Identifier_SelfAddressing>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$Identifier_SelfSigningCopyWith<$Res> {
  factory _$$Identifier_SelfSigningCopyWith(_$Identifier_SelfSigning value,
          $Res Function(_$Identifier_SelfSigning) then) =
      __$$Identifier_SelfSigningCopyWithImpl<$Res>;
  $Res call({Signature field0});
}

/// @nodoc
class __$$Identifier_SelfSigningCopyWithImpl<$Res>
    extends _$IdentifierCopyWithImpl<$Res>
    implements _$$Identifier_SelfSigningCopyWith<$Res> {
  __$$Identifier_SelfSigningCopyWithImpl(_$Identifier_SelfSigning _value,
      $Res Function(_$Identifier_SelfSigning) _then)
      : super(_value, (v) => _then(v as _$Identifier_SelfSigning));

  @override
  _$Identifier_SelfSigning get _value =>
      super._value as _$Identifier_SelfSigning;

  @override
  $Res call({
    Object? field0 = freezed,
  }) {
    return _then(_$Identifier_SelfSigning(
      field0 == freezed
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as Signature,
    ));
  }
}

/// @nodoc

class _$Identifier_SelfSigning implements Identifier_SelfSigning {
  const _$Identifier_SelfSigning(this.field0);

  @override
  final Signature field0;

  @override
  String toString() {
    return 'Identifier.selfSigning(field0: $field0)';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$Identifier_SelfSigning &&
            const DeepCollectionEquality().equals(other.field0, field0));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(field0));

  @JsonKey(ignore: true)
  @override
  _$$Identifier_SelfSigningCopyWith<_$Identifier_SelfSigning> get copyWith =>
      __$$Identifier_SelfSigningCopyWithImpl<_$Identifier_SelfSigning>(
          this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(PublicKey field0) basic,
    required TResult Function(Digest field0) selfAddressing,
    required TResult Function(Signature field0) selfSigning,
  }) {
    return selfSigning(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function(PublicKey field0)? basic,
    TResult Function(Digest field0)? selfAddressing,
    TResult Function(Signature field0)? selfSigning,
  }) {
    return selfSigning?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(PublicKey field0)? basic,
    TResult Function(Digest field0)? selfAddressing,
    TResult Function(Signature field0)? selfSigning,
    required TResult orElse(),
  }) {
    if (selfSigning != null) {
      return selfSigning(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Identifier_Basic value) basic,
    required TResult Function(Identifier_SelfAddressing value) selfAddressing,
    required TResult Function(Identifier_SelfSigning value) selfSigning,
  }) {
    return selfSigning(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(Identifier_Basic value)? basic,
    TResult Function(Identifier_SelfAddressing value)? selfAddressing,
    TResult Function(Identifier_SelfSigning value)? selfSigning,
  }) {
    return selfSigning?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Identifier_Basic value)? basic,
    TResult Function(Identifier_SelfAddressing value)? selfAddressing,
    TResult Function(Identifier_SelfSigning value)? selfSigning,
    required TResult orElse(),
  }) {
    if (selfSigning != null) {
      return selfSigning(this);
    }
    return orElse();
  }
}

abstract class Identifier_SelfSigning implements Identifier {
  const factory Identifier_SelfSigning(final Signature field0) =
      _$Identifier_SelfSigning;

  Signature get field0;
  @JsonKey(ignore: true)
  _$$Identifier_SelfSigningCopyWith<_$Identifier_SelfSigning> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
mixin _$SelfAddressing {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() blake3256,
    required TResult Function() sha3256,
    required TResult Function() sha2256,
    required TResult Function() blake3512,
    required TResult Function() sha3512,
    required TResult Function() blake2B512,
    required TResult Function() sha2512,
    required TResult Function(Uint8List field0) blake2B256,
    required TResult Function(Uint8List field0) blake2S256,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SelfAddressing_Blake3_256 value) blake3256,
    required TResult Function(SelfAddressing_SHA3_256 value) sha3256,
    required TResult Function(SelfAddressing_SHA2_256 value) sha2256,
    required TResult Function(SelfAddressing_Blake3_512 value) blake3512,
    required TResult Function(SelfAddressing_SHA3_512 value) sha3512,
    required TResult Function(SelfAddressing_Blake2B512 value) blake2B512,
    required TResult Function(SelfAddressing_SHA2_512 value) sha2512,
    required TResult Function(SelfAddressing_Blake2B256 value) blake2B256,
    required TResult Function(SelfAddressing_Blake2S256 value) blake2S256,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SelfAddressingCopyWith<$Res> {
  factory $SelfAddressingCopyWith(
          SelfAddressing value, $Res Function(SelfAddressing) then) =
      _$SelfAddressingCopyWithImpl<$Res>;
}

/// @nodoc
class _$SelfAddressingCopyWithImpl<$Res>
    implements $SelfAddressingCopyWith<$Res> {
  _$SelfAddressingCopyWithImpl(this._value, this._then);

  final SelfAddressing _value;
  // ignore: unused_field
  final $Res Function(SelfAddressing) _then;
}

/// @nodoc
abstract class _$$SelfAddressing_Blake3_256CopyWith<$Res> {
  factory _$$SelfAddressing_Blake3_256CopyWith(
          _$SelfAddressing_Blake3_256 value,
          $Res Function(_$SelfAddressing_Blake3_256) then) =
      __$$SelfAddressing_Blake3_256CopyWithImpl<$Res>;
}

/// @nodoc
class __$$SelfAddressing_Blake3_256CopyWithImpl<$Res>
    extends _$SelfAddressingCopyWithImpl<$Res>
    implements _$$SelfAddressing_Blake3_256CopyWith<$Res> {
  __$$SelfAddressing_Blake3_256CopyWithImpl(_$SelfAddressing_Blake3_256 _value,
      $Res Function(_$SelfAddressing_Blake3_256) _then)
      : super(_value, (v) => _then(v as _$SelfAddressing_Blake3_256));

  @override
  _$SelfAddressing_Blake3_256 get _value =>
      super._value as _$SelfAddressing_Blake3_256;
}

/// @nodoc

class _$SelfAddressing_Blake3_256 implements SelfAddressing_Blake3_256 {
  const _$SelfAddressing_Blake3_256();

  @override
  String toString() {
    return 'SelfAddressing.blake3256()';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SelfAddressing_Blake3_256);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() blake3256,
    required TResult Function() sha3256,
    required TResult Function() sha2256,
    required TResult Function() blake3512,
    required TResult Function() sha3512,
    required TResult Function() blake2B512,
    required TResult Function() sha2512,
    required TResult Function(Uint8List field0) blake2B256,
    required TResult Function(Uint8List field0) blake2S256,
  }) {
    return blake3256();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
  }) {
    return blake3256?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
    required TResult orElse(),
  }) {
    if (blake3256 != null) {
      return blake3256();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SelfAddressing_Blake3_256 value) blake3256,
    required TResult Function(SelfAddressing_SHA3_256 value) sha3256,
    required TResult Function(SelfAddressing_SHA2_256 value) sha2256,
    required TResult Function(SelfAddressing_Blake3_512 value) blake3512,
    required TResult Function(SelfAddressing_SHA3_512 value) sha3512,
    required TResult Function(SelfAddressing_Blake2B512 value) blake2B512,
    required TResult Function(SelfAddressing_SHA2_512 value) sha2512,
    required TResult Function(SelfAddressing_Blake2B256 value) blake2B256,
    required TResult Function(SelfAddressing_Blake2S256 value) blake2S256,
  }) {
    return blake3256(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
  }) {
    return blake3256?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
    required TResult orElse(),
  }) {
    if (blake3256 != null) {
      return blake3256(this);
    }
    return orElse();
  }
}

abstract class SelfAddressing_Blake3_256 implements SelfAddressing {
  const factory SelfAddressing_Blake3_256() = _$SelfAddressing_Blake3_256;
}

/// @nodoc
abstract class _$$SelfAddressing_SHA3_256CopyWith<$Res> {
  factory _$$SelfAddressing_SHA3_256CopyWith(_$SelfAddressing_SHA3_256 value,
          $Res Function(_$SelfAddressing_SHA3_256) then) =
      __$$SelfAddressing_SHA3_256CopyWithImpl<$Res>;
}

/// @nodoc
class __$$SelfAddressing_SHA3_256CopyWithImpl<$Res>
    extends _$SelfAddressingCopyWithImpl<$Res>
    implements _$$SelfAddressing_SHA3_256CopyWith<$Res> {
  __$$SelfAddressing_SHA3_256CopyWithImpl(_$SelfAddressing_SHA3_256 _value,
      $Res Function(_$SelfAddressing_SHA3_256) _then)
      : super(_value, (v) => _then(v as _$SelfAddressing_SHA3_256));

  @override
  _$SelfAddressing_SHA3_256 get _value =>
      super._value as _$SelfAddressing_SHA3_256;
}

/// @nodoc

class _$SelfAddressing_SHA3_256 implements SelfAddressing_SHA3_256 {
  const _$SelfAddressing_SHA3_256();

  @override
  String toString() {
    return 'SelfAddressing.sha3256()';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SelfAddressing_SHA3_256);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() blake3256,
    required TResult Function() sha3256,
    required TResult Function() sha2256,
    required TResult Function() blake3512,
    required TResult Function() sha3512,
    required TResult Function() blake2B512,
    required TResult Function() sha2512,
    required TResult Function(Uint8List field0) blake2B256,
    required TResult Function(Uint8List field0) blake2S256,
  }) {
    return sha3256();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
  }) {
    return sha3256?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
    required TResult orElse(),
  }) {
    if (sha3256 != null) {
      return sha3256();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SelfAddressing_Blake3_256 value) blake3256,
    required TResult Function(SelfAddressing_SHA3_256 value) sha3256,
    required TResult Function(SelfAddressing_SHA2_256 value) sha2256,
    required TResult Function(SelfAddressing_Blake3_512 value) blake3512,
    required TResult Function(SelfAddressing_SHA3_512 value) sha3512,
    required TResult Function(SelfAddressing_Blake2B512 value) blake2B512,
    required TResult Function(SelfAddressing_SHA2_512 value) sha2512,
    required TResult Function(SelfAddressing_Blake2B256 value) blake2B256,
    required TResult Function(SelfAddressing_Blake2S256 value) blake2S256,
  }) {
    return sha3256(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
  }) {
    return sha3256?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
    required TResult orElse(),
  }) {
    if (sha3256 != null) {
      return sha3256(this);
    }
    return orElse();
  }
}

abstract class SelfAddressing_SHA3_256 implements SelfAddressing {
  const factory SelfAddressing_SHA3_256() = _$SelfAddressing_SHA3_256;
}

/// @nodoc
abstract class _$$SelfAddressing_SHA2_256CopyWith<$Res> {
  factory _$$SelfAddressing_SHA2_256CopyWith(_$SelfAddressing_SHA2_256 value,
          $Res Function(_$SelfAddressing_SHA2_256) then) =
      __$$SelfAddressing_SHA2_256CopyWithImpl<$Res>;
}

/// @nodoc
class __$$SelfAddressing_SHA2_256CopyWithImpl<$Res>
    extends _$SelfAddressingCopyWithImpl<$Res>
    implements _$$SelfAddressing_SHA2_256CopyWith<$Res> {
  __$$SelfAddressing_SHA2_256CopyWithImpl(_$SelfAddressing_SHA2_256 _value,
      $Res Function(_$SelfAddressing_SHA2_256) _then)
      : super(_value, (v) => _then(v as _$SelfAddressing_SHA2_256));

  @override
  _$SelfAddressing_SHA2_256 get _value =>
      super._value as _$SelfAddressing_SHA2_256;
}

/// @nodoc

class _$SelfAddressing_SHA2_256 implements SelfAddressing_SHA2_256 {
  const _$SelfAddressing_SHA2_256();

  @override
  String toString() {
    return 'SelfAddressing.sha2256()';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SelfAddressing_SHA2_256);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() blake3256,
    required TResult Function() sha3256,
    required TResult Function() sha2256,
    required TResult Function() blake3512,
    required TResult Function() sha3512,
    required TResult Function() blake2B512,
    required TResult Function() sha2512,
    required TResult Function(Uint8List field0) blake2B256,
    required TResult Function(Uint8List field0) blake2S256,
  }) {
    return sha2256();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
  }) {
    return sha2256?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
    required TResult orElse(),
  }) {
    if (sha2256 != null) {
      return sha2256();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SelfAddressing_Blake3_256 value) blake3256,
    required TResult Function(SelfAddressing_SHA3_256 value) sha3256,
    required TResult Function(SelfAddressing_SHA2_256 value) sha2256,
    required TResult Function(SelfAddressing_Blake3_512 value) blake3512,
    required TResult Function(SelfAddressing_SHA3_512 value) sha3512,
    required TResult Function(SelfAddressing_Blake2B512 value) blake2B512,
    required TResult Function(SelfAddressing_SHA2_512 value) sha2512,
    required TResult Function(SelfAddressing_Blake2B256 value) blake2B256,
    required TResult Function(SelfAddressing_Blake2S256 value) blake2S256,
  }) {
    return sha2256(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
  }) {
    return sha2256?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
    required TResult orElse(),
  }) {
    if (sha2256 != null) {
      return sha2256(this);
    }
    return orElse();
  }
}

abstract class SelfAddressing_SHA2_256 implements SelfAddressing {
  const factory SelfAddressing_SHA2_256() = _$SelfAddressing_SHA2_256;
}

/// @nodoc
abstract class _$$SelfAddressing_Blake3_512CopyWith<$Res> {
  factory _$$SelfAddressing_Blake3_512CopyWith(
          _$SelfAddressing_Blake3_512 value,
          $Res Function(_$SelfAddressing_Blake3_512) then) =
      __$$SelfAddressing_Blake3_512CopyWithImpl<$Res>;
}

/// @nodoc
class __$$SelfAddressing_Blake3_512CopyWithImpl<$Res>
    extends _$SelfAddressingCopyWithImpl<$Res>
    implements _$$SelfAddressing_Blake3_512CopyWith<$Res> {
  __$$SelfAddressing_Blake3_512CopyWithImpl(_$SelfAddressing_Blake3_512 _value,
      $Res Function(_$SelfAddressing_Blake3_512) _then)
      : super(_value, (v) => _then(v as _$SelfAddressing_Blake3_512));

  @override
  _$SelfAddressing_Blake3_512 get _value =>
      super._value as _$SelfAddressing_Blake3_512;
}

/// @nodoc

class _$SelfAddressing_Blake3_512 implements SelfAddressing_Blake3_512 {
  const _$SelfAddressing_Blake3_512();

  @override
  String toString() {
    return 'SelfAddressing.blake3512()';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SelfAddressing_Blake3_512);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() blake3256,
    required TResult Function() sha3256,
    required TResult Function() sha2256,
    required TResult Function() blake3512,
    required TResult Function() sha3512,
    required TResult Function() blake2B512,
    required TResult Function() sha2512,
    required TResult Function(Uint8List field0) blake2B256,
    required TResult Function(Uint8List field0) blake2S256,
  }) {
    return blake3512();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
  }) {
    return blake3512?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
    required TResult orElse(),
  }) {
    if (blake3512 != null) {
      return blake3512();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SelfAddressing_Blake3_256 value) blake3256,
    required TResult Function(SelfAddressing_SHA3_256 value) sha3256,
    required TResult Function(SelfAddressing_SHA2_256 value) sha2256,
    required TResult Function(SelfAddressing_Blake3_512 value) blake3512,
    required TResult Function(SelfAddressing_SHA3_512 value) sha3512,
    required TResult Function(SelfAddressing_Blake2B512 value) blake2B512,
    required TResult Function(SelfAddressing_SHA2_512 value) sha2512,
    required TResult Function(SelfAddressing_Blake2B256 value) blake2B256,
    required TResult Function(SelfAddressing_Blake2S256 value) blake2S256,
  }) {
    return blake3512(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
  }) {
    return blake3512?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
    required TResult orElse(),
  }) {
    if (blake3512 != null) {
      return blake3512(this);
    }
    return orElse();
  }
}

abstract class SelfAddressing_Blake3_512 implements SelfAddressing {
  const factory SelfAddressing_Blake3_512() = _$SelfAddressing_Blake3_512;
}

/// @nodoc
abstract class _$$SelfAddressing_SHA3_512CopyWith<$Res> {
  factory _$$SelfAddressing_SHA3_512CopyWith(_$SelfAddressing_SHA3_512 value,
          $Res Function(_$SelfAddressing_SHA3_512) then) =
      __$$SelfAddressing_SHA3_512CopyWithImpl<$Res>;
}

/// @nodoc
class __$$SelfAddressing_SHA3_512CopyWithImpl<$Res>
    extends _$SelfAddressingCopyWithImpl<$Res>
    implements _$$SelfAddressing_SHA3_512CopyWith<$Res> {
  __$$SelfAddressing_SHA3_512CopyWithImpl(_$SelfAddressing_SHA3_512 _value,
      $Res Function(_$SelfAddressing_SHA3_512) _then)
      : super(_value, (v) => _then(v as _$SelfAddressing_SHA3_512));

  @override
  _$SelfAddressing_SHA3_512 get _value =>
      super._value as _$SelfAddressing_SHA3_512;
}

/// @nodoc

class _$SelfAddressing_SHA3_512 implements SelfAddressing_SHA3_512 {
  const _$SelfAddressing_SHA3_512();

  @override
  String toString() {
    return 'SelfAddressing.sha3512()';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SelfAddressing_SHA3_512);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() blake3256,
    required TResult Function() sha3256,
    required TResult Function() sha2256,
    required TResult Function() blake3512,
    required TResult Function() sha3512,
    required TResult Function() blake2B512,
    required TResult Function() sha2512,
    required TResult Function(Uint8List field0) blake2B256,
    required TResult Function(Uint8List field0) blake2S256,
  }) {
    return sha3512();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
  }) {
    return sha3512?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
    required TResult orElse(),
  }) {
    if (sha3512 != null) {
      return sha3512();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SelfAddressing_Blake3_256 value) blake3256,
    required TResult Function(SelfAddressing_SHA3_256 value) sha3256,
    required TResult Function(SelfAddressing_SHA2_256 value) sha2256,
    required TResult Function(SelfAddressing_Blake3_512 value) blake3512,
    required TResult Function(SelfAddressing_SHA3_512 value) sha3512,
    required TResult Function(SelfAddressing_Blake2B512 value) blake2B512,
    required TResult Function(SelfAddressing_SHA2_512 value) sha2512,
    required TResult Function(SelfAddressing_Blake2B256 value) blake2B256,
    required TResult Function(SelfAddressing_Blake2S256 value) blake2S256,
  }) {
    return sha3512(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
  }) {
    return sha3512?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
    required TResult orElse(),
  }) {
    if (sha3512 != null) {
      return sha3512(this);
    }
    return orElse();
  }
}

abstract class SelfAddressing_SHA3_512 implements SelfAddressing {
  const factory SelfAddressing_SHA3_512() = _$SelfAddressing_SHA3_512;
}

/// @nodoc
abstract class _$$SelfAddressing_Blake2B512CopyWith<$Res> {
  factory _$$SelfAddressing_Blake2B512CopyWith(
          _$SelfAddressing_Blake2B512 value,
          $Res Function(_$SelfAddressing_Blake2B512) then) =
      __$$SelfAddressing_Blake2B512CopyWithImpl<$Res>;
}

/// @nodoc
class __$$SelfAddressing_Blake2B512CopyWithImpl<$Res>
    extends _$SelfAddressingCopyWithImpl<$Res>
    implements _$$SelfAddressing_Blake2B512CopyWith<$Res> {
  __$$SelfAddressing_Blake2B512CopyWithImpl(_$SelfAddressing_Blake2B512 _value,
      $Res Function(_$SelfAddressing_Blake2B512) _then)
      : super(_value, (v) => _then(v as _$SelfAddressing_Blake2B512));

  @override
  _$SelfAddressing_Blake2B512 get _value =>
      super._value as _$SelfAddressing_Blake2B512;
}

/// @nodoc

class _$SelfAddressing_Blake2B512 implements SelfAddressing_Blake2B512 {
  const _$SelfAddressing_Blake2B512();

  @override
  String toString() {
    return 'SelfAddressing.blake2B512()';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SelfAddressing_Blake2B512);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() blake3256,
    required TResult Function() sha3256,
    required TResult Function() sha2256,
    required TResult Function() blake3512,
    required TResult Function() sha3512,
    required TResult Function() blake2B512,
    required TResult Function() sha2512,
    required TResult Function(Uint8List field0) blake2B256,
    required TResult Function(Uint8List field0) blake2S256,
  }) {
    return blake2B512();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
  }) {
    return blake2B512?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
    required TResult orElse(),
  }) {
    if (blake2B512 != null) {
      return blake2B512();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SelfAddressing_Blake3_256 value) blake3256,
    required TResult Function(SelfAddressing_SHA3_256 value) sha3256,
    required TResult Function(SelfAddressing_SHA2_256 value) sha2256,
    required TResult Function(SelfAddressing_Blake3_512 value) blake3512,
    required TResult Function(SelfAddressing_SHA3_512 value) sha3512,
    required TResult Function(SelfAddressing_Blake2B512 value) blake2B512,
    required TResult Function(SelfAddressing_SHA2_512 value) sha2512,
    required TResult Function(SelfAddressing_Blake2B256 value) blake2B256,
    required TResult Function(SelfAddressing_Blake2S256 value) blake2S256,
  }) {
    return blake2B512(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
  }) {
    return blake2B512?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
    required TResult orElse(),
  }) {
    if (blake2B512 != null) {
      return blake2B512(this);
    }
    return orElse();
  }
}

abstract class SelfAddressing_Blake2B512 implements SelfAddressing {
  const factory SelfAddressing_Blake2B512() = _$SelfAddressing_Blake2B512;
}

/// @nodoc
abstract class _$$SelfAddressing_SHA2_512CopyWith<$Res> {
  factory _$$SelfAddressing_SHA2_512CopyWith(_$SelfAddressing_SHA2_512 value,
          $Res Function(_$SelfAddressing_SHA2_512) then) =
      __$$SelfAddressing_SHA2_512CopyWithImpl<$Res>;
}

/// @nodoc
class __$$SelfAddressing_SHA2_512CopyWithImpl<$Res>
    extends _$SelfAddressingCopyWithImpl<$Res>
    implements _$$SelfAddressing_SHA2_512CopyWith<$Res> {
  __$$SelfAddressing_SHA2_512CopyWithImpl(_$SelfAddressing_SHA2_512 _value,
      $Res Function(_$SelfAddressing_SHA2_512) _then)
      : super(_value, (v) => _then(v as _$SelfAddressing_SHA2_512));

  @override
  _$SelfAddressing_SHA2_512 get _value =>
      super._value as _$SelfAddressing_SHA2_512;
}

/// @nodoc

class _$SelfAddressing_SHA2_512 implements SelfAddressing_SHA2_512 {
  const _$SelfAddressing_SHA2_512();

  @override
  String toString() {
    return 'SelfAddressing.sha2512()';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SelfAddressing_SHA2_512);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() blake3256,
    required TResult Function() sha3256,
    required TResult Function() sha2256,
    required TResult Function() blake3512,
    required TResult Function() sha3512,
    required TResult Function() blake2B512,
    required TResult Function() sha2512,
    required TResult Function(Uint8List field0) blake2B256,
    required TResult Function(Uint8List field0) blake2S256,
  }) {
    return sha2512();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
  }) {
    return sha2512?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
    required TResult orElse(),
  }) {
    if (sha2512 != null) {
      return sha2512();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SelfAddressing_Blake3_256 value) blake3256,
    required TResult Function(SelfAddressing_SHA3_256 value) sha3256,
    required TResult Function(SelfAddressing_SHA2_256 value) sha2256,
    required TResult Function(SelfAddressing_Blake3_512 value) blake3512,
    required TResult Function(SelfAddressing_SHA3_512 value) sha3512,
    required TResult Function(SelfAddressing_Blake2B512 value) blake2B512,
    required TResult Function(SelfAddressing_SHA2_512 value) sha2512,
    required TResult Function(SelfAddressing_Blake2B256 value) blake2B256,
    required TResult Function(SelfAddressing_Blake2S256 value) blake2S256,
  }) {
    return sha2512(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
  }) {
    return sha2512?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
    required TResult orElse(),
  }) {
    if (sha2512 != null) {
      return sha2512(this);
    }
    return orElse();
  }
}

abstract class SelfAddressing_SHA2_512 implements SelfAddressing {
  const factory SelfAddressing_SHA2_512() = _$SelfAddressing_SHA2_512;
}

/// @nodoc
abstract class _$$SelfAddressing_Blake2B256CopyWith<$Res> {
  factory _$$SelfAddressing_Blake2B256CopyWith(
          _$SelfAddressing_Blake2B256 value,
          $Res Function(_$SelfAddressing_Blake2B256) then) =
      __$$SelfAddressing_Blake2B256CopyWithImpl<$Res>;
  $Res call({Uint8List field0});
}

/// @nodoc
class __$$SelfAddressing_Blake2B256CopyWithImpl<$Res>
    extends _$SelfAddressingCopyWithImpl<$Res>
    implements _$$SelfAddressing_Blake2B256CopyWith<$Res> {
  __$$SelfAddressing_Blake2B256CopyWithImpl(_$SelfAddressing_Blake2B256 _value,
      $Res Function(_$SelfAddressing_Blake2B256) _then)
      : super(_value, (v) => _then(v as _$SelfAddressing_Blake2B256));

  @override
  _$SelfAddressing_Blake2B256 get _value =>
      super._value as _$SelfAddressing_Blake2B256;

  @override
  $Res call({
    Object? field0 = freezed,
  }) {
    return _then(_$SelfAddressing_Blake2B256(
      field0 == freezed
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$SelfAddressing_Blake2B256 implements SelfAddressing_Blake2B256 {
  const _$SelfAddressing_Blake2B256(this.field0);

  @override
  final Uint8List field0;

  @override
  String toString() {
    return 'SelfAddressing.blake2B256(field0: $field0)';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SelfAddressing_Blake2B256 &&
            const DeepCollectionEquality().equals(other.field0, field0));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(field0));

  @JsonKey(ignore: true)
  @override
  _$$SelfAddressing_Blake2B256CopyWith<_$SelfAddressing_Blake2B256>
      get copyWith => __$$SelfAddressing_Blake2B256CopyWithImpl<
          _$SelfAddressing_Blake2B256>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() blake3256,
    required TResult Function() sha3256,
    required TResult Function() sha2256,
    required TResult Function() blake3512,
    required TResult Function() sha3512,
    required TResult Function() blake2B512,
    required TResult Function() sha2512,
    required TResult Function(Uint8List field0) blake2B256,
    required TResult Function(Uint8List field0) blake2S256,
  }) {
    return blake2B256(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
  }) {
    return blake2B256?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
    required TResult orElse(),
  }) {
    if (blake2B256 != null) {
      return blake2B256(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SelfAddressing_Blake3_256 value) blake3256,
    required TResult Function(SelfAddressing_SHA3_256 value) sha3256,
    required TResult Function(SelfAddressing_SHA2_256 value) sha2256,
    required TResult Function(SelfAddressing_Blake3_512 value) blake3512,
    required TResult Function(SelfAddressing_SHA3_512 value) sha3512,
    required TResult Function(SelfAddressing_Blake2B512 value) blake2B512,
    required TResult Function(SelfAddressing_SHA2_512 value) sha2512,
    required TResult Function(SelfAddressing_Blake2B256 value) blake2B256,
    required TResult Function(SelfAddressing_Blake2S256 value) blake2S256,
  }) {
    return blake2B256(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
  }) {
    return blake2B256?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
    required TResult orElse(),
  }) {
    if (blake2B256 != null) {
      return blake2B256(this);
    }
    return orElse();
  }
}

abstract class SelfAddressing_Blake2B256 implements SelfAddressing {
  const factory SelfAddressing_Blake2B256(final Uint8List field0) =
      _$SelfAddressing_Blake2B256;

  Uint8List get field0;
  @JsonKey(ignore: true)
  _$$SelfAddressing_Blake2B256CopyWith<_$SelfAddressing_Blake2B256>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$SelfAddressing_Blake2S256CopyWith<$Res> {
  factory _$$SelfAddressing_Blake2S256CopyWith(
          _$SelfAddressing_Blake2S256 value,
          $Res Function(_$SelfAddressing_Blake2S256) then) =
      __$$SelfAddressing_Blake2S256CopyWithImpl<$Res>;
  $Res call({Uint8List field0});
}

/// @nodoc
class __$$SelfAddressing_Blake2S256CopyWithImpl<$Res>
    extends _$SelfAddressingCopyWithImpl<$Res>
    implements _$$SelfAddressing_Blake2S256CopyWith<$Res> {
  __$$SelfAddressing_Blake2S256CopyWithImpl(_$SelfAddressing_Blake2S256 _value,
      $Res Function(_$SelfAddressing_Blake2S256) _then)
      : super(_value, (v) => _then(v as _$SelfAddressing_Blake2S256));

  @override
  _$SelfAddressing_Blake2S256 get _value =>
      super._value as _$SelfAddressing_Blake2S256;

  @override
  $Res call({
    Object? field0 = freezed,
  }) {
    return _then(_$SelfAddressing_Blake2S256(
      field0 == freezed
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as Uint8List,
    ));
  }
}

/// @nodoc

class _$SelfAddressing_Blake2S256 implements SelfAddressing_Blake2S256 {
  const _$SelfAddressing_Blake2S256(this.field0);

  @override
  final Uint8List field0;

  @override
  String toString() {
    return 'SelfAddressing.blake2S256(field0: $field0)';
  }

  @override
  bool operator ==(dynamic other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SelfAddressing_Blake2S256 &&
            const DeepCollectionEquality().equals(other.field0, field0));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(field0));

  @JsonKey(ignore: true)
  @override
  _$$SelfAddressing_Blake2S256CopyWith<_$SelfAddressing_Blake2S256>
      get copyWith => __$$SelfAddressing_Blake2S256CopyWithImpl<
          _$SelfAddressing_Blake2S256>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() blake3256,
    required TResult Function() sha3256,
    required TResult Function() sha2256,
    required TResult Function() blake3512,
    required TResult Function() sha3512,
    required TResult Function() blake2B512,
    required TResult Function() sha2512,
    required TResult Function(Uint8List field0) blake2B256,
    required TResult Function(Uint8List field0) blake2S256,
  }) {
    return blake2S256(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
  }) {
    return blake2S256?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? blake3256,
    TResult Function()? sha3256,
    TResult Function()? sha2256,
    TResult Function()? blake3512,
    TResult Function()? sha3512,
    TResult Function()? blake2B512,
    TResult Function()? sha2512,
    TResult Function(Uint8List field0)? blake2B256,
    TResult Function(Uint8List field0)? blake2S256,
    required TResult orElse(),
  }) {
    if (blake2S256 != null) {
      return blake2S256(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SelfAddressing_Blake3_256 value) blake3256,
    required TResult Function(SelfAddressing_SHA3_256 value) sha3256,
    required TResult Function(SelfAddressing_SHA2_256 value) sha2256,
    required TResult Function(SelfAddressing_Blake3_512 value) blake3512,
    required TResult Function(SelfAddressing_SHA3_512 value) sha3512,
    required TResult Function(SelfAddressing_Blake2B512 value) blake2B512,
    required TResult Function(SelfAddressing_SHA2_512 value) sha2512,
    required TResult Function(SelfAddressing_Blake2B256 value) blake2B256,
    required TResult Function(SelfAddressing_Blake2S256 value) blake2S256,
  }) {
    return blake2S256(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
  }) {
    return blake2S256?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SelfAddressing_Blake3_256 value)? blake3256,
    TResult Function(SelfAddressing_SHA3_256 value)? sha3256,
    TResult Function(SelfAddressing_SHA2_256 value)? sha2256,
    TResult Function(SelfAddressing_Blake3_512 value)? blake3512,
    TResult Function(SelfAddressing_SHA3_512 value)? sha3512,
    TResult Function(SelfAddressing_Blake2B512 value)? blake2B512,
    TResult Function(SelfAddressing_SHA2_512 value)? sha2512,
    TResult Function(SelfAddressing_Blake2B256 value)? blake2B256,
    TResult Function(SelfAddressing_Blake2S256 value)? blake2S256,
    required TResult orElse(),
  }) {
    if (blake2S256 != null) {
      return blake2S256(this);
    }
    return orElse();
  }
}

abstract class SelfAddressing_Blake2S256 implements SelfAddressing {
  const factory SelfAddressing_Blake2S256(final Uint8List field0) =
      _$SelfAddressing_Blake2S256;

  Uint8List get field0;
  @JsonKey(ignore: true)
  _$$SelfAddressing_Blake2S256CopyWith<_$SelfAddressing_Blake2S256>
      get copyWith => throw _privateConstructorUsedError;
}
