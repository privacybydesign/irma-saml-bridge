import { postJson } from './transport.mjs';

// Global variable defining whether an error already occurred.
let errorOccurred = false;
export const reportError = (errorUrl, error) => {
    // An error already occurred; limit amount of errors to 1.
    if (errorOccurred) {
        return null;
    }
    errorOccurred = true;
    return postJson(errorUrl, error);
};
