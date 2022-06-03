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