import {
  AnchoreHttpError,
  AnchoreInvalidResponseError,
  AnchoreNetworkError,
  AnchoreResponseTooLargeError,
  AnchoreTimeoutError,
} from "../anchore/errors.js";

/** Safe operator-facing message (no secret echo). */
export function anchoreFailureMessage(err: unknown): string {
  if (err instanceof AnchoreHttpError) {
    return err.userMessage;
  }
  if (err instanceof AnchoreTimeoutError) {
    return err.message;
  }
  if (err instanceof AnchoreNetworkError) {
    return err.message;
  }
  if (err instanceof AnchoreInvalidResponseError) {
    return err.message;
  }
  if (err instanceof AnchoreResponseTooLargeError) {
    return err.message;
  }
  if (err instanceof Error) {
    return err.message;
  }
  return "Unexpected error while calling Anchore.";
}
