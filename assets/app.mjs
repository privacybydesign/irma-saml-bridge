import React from 'react';
import { createRoot } from 'react-dom/client';

import YiviLogin from './components/YiviLogin';
import { reportError } from "./js/errors";

window.onload = () => {
    const container = document.getElementById('root');
    if (container !== null) {
        const root = createRoot(container);
        root.render(<YiviLogin
            server={window.IRMA_SERVER}
            error={window.ERROR}
            sessionData={window.SESSION_DATA}
            language={window.LANGUAGE}
            assertUrl={window.ASSERT_URL}
            errorAssertUrl={window.ERROR_ASSERT_URL}
            assertParameters={window.ASSERT_PARAMETERS}
        />)
    }
};

window.onerror = (message, source, lineno, colno, error) => {
    console.error('Something went wrong', error);
    return reportError(window.ERROR_URL, { message, source, lineno, colno });
};

window.addEventListener("unhandledrejection", (error) =>
    reportError(window.ERROR_URL, error));
