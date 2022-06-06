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
