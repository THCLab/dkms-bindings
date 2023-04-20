///An exception thrown when it is not possible to create a database in provided directory
class UnavailableDirectoryException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  UnavailableDirectoryException(this.cause);
  @override
  String toString() => "UnavailableDirectoryException: $cause";
}

///An exception thrown when the initial configuration is incorrect
class IncorrectOptionalConfigsException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  IncorrectOptionalConfigsException(this.cause);
  @override
  String toString() => "IncorrectOptionalConfigsException: $cause";
}

///An exception thrown when witnesses oobis are not correct.
class IncorrectWitnessOobiException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  IncorrectWitnessOobiException(this.cause);
  @override
  String toString() => "IncorrectWitnessOobiException: $cause";
}

///An exception thrown when controller has not been initialized.
class ControllerNotInitializedException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  ControllerNotInitializedException(this.cause);
  @override
  String toString() => "ControllerNotInitializedException: $cause";
}

///An exception thrown when the key provided is in incorrect format.
class IncorrectKeyFormatException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  IncorrectKeyFormatException(this.cause);
  @override
  String toString() => "IncorrectKeyFormatException: $cause";
}

///An exception thrown when the oobi provided is connecting to a port, where nobody is listening.
class OobiResolvingErrorException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  OobiResolvingErrorException(this.cause);
  @override
  String toString() => "OobiResolvingErrorException: $cause";
}

///An exception thrown when the signature provided is not a hex string.
class IncorrectSignatureException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  IncorrectSignatureException(this.cause);
  @override
  String toString() => "IncorrectSignatureException: $cause";
}

///An exception thrown when the string provided as event is not a correct event
class WrongEventException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  WrongEventException(this.cause);
  @override
  String toString() => "WrongEventException: $cause";
}

///An exception thrown when the controller provided to function has an incorrect identifier
class IdentifierException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  IdentifierException(this.cause);
  @override
  String toString() => "IdentifierException: $cause";
}

///An exception thrown when the witness provided to function cannot be parsed.
class WitnessParsingException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  WitnessParsingException(this.cause);
  @override
  String toString() => "WitnessParsingException: $cause";
}

///An exception thrown when the witness prefix is in the wrong scheme.
class ImproperWitnessPrefixException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  ImproperWitnessPrefixException(this.cause);
  @override
  String toString() => "ImproperWitnessPrefixException: $cause";
}

///An exception thrown when the event signature does not match the event keys.
class SignatureVerificationException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  SignatureVerificationException(this.cause);
  @override
  String toString() => "SignatureVerificationException: $cause";
}

///An exception thrown when the watcher oobi is incorrect
class IncorrectWatcherOobiException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  IncorrectWatcherOobiException(this.cause);
  @override
  String toString() => "IncorrectWatcherOobiException: $cause";
}

///An exception thrown when the oobi is incorrect
class IncorrectOobiException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  IncorrectOobiException(this.cause);

  @override
  String toString() => "IncorrectOobiException: $cause";
}

///An exception thrown when the dynamic library for a platform has not been implemented
class LibraryNotImplementedException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  LibraryNotImplementedException(this.cause);

  @override
  String toString() => "LibraryNotImplementedException: $cause";
}

///An exception thrown when the dynamic library is not found
class AttachmentException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  AttachmentException(this.cause);

  @override
  String toString() => "AttachmentException: $cause";
}

///An exception thrown when the dynamic library is not found
class LibraryNotFoundException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  LibraryNotFoundException(this.cause);

  @override
  String toString() => "LibraryNotFoundException: $cause";
}

///An exception thrown when the SAI is incorrect
class SelfAddressingIndentifierException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  SelfAddressingIndentifierException(this.cause);

  @override
  String toString() => "SelfAddressingIndentifierException: $cause";
}

///An exception thrown when the witness is not listening
class NetworkErrorException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  NetworkErrorException(this.cause);

  @override
  String toString() => "NetworkErrorException: $cause";
}

///An exception thrown when the signature threshold is lower than 0 or bigger than key list length
class ImproperSignatureThresholdException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  ImproperSignatureThresholdException(this.cause);

  @override
  String toString() => "ImproperSignatureThresholdException: $cause";
}

///An exception thrown when the witness threshold is lower than 0 or bigger than witness list length
class ImproperWitnessThresholdException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  ImproperWitnessThresholdException(this.cause);

  @override
  String toString() => "ImproperWitnessThresholdException: $cause";
}

///An exception thrown when the format of the CESR string is incorrect
class CesrFormatException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  CesrFormatException(this.cause);

  @override
  String toString() => "CesrFormatException: $cause";
}

///An exception thrown when the CESR signature (a product of calling `signToCesr`) is incorrect
class WrongCesrSignatureException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  WrongCesrSignatureException(this.cause);

  @override
  String toString() => "WrongCesrSignatureException: $cause";
}

///An exception thrown when the verification of CESR signature fails
class CesrVerificationException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  CesrVerificationException(this.cause);

  @override
  String toString() => "CesrVerificationException: $cause";
}
