import YiviCore from '@privacybydesign/yivi-core';
import YiviClient from '@privacybydesign/yivi-client';
import { postJson } from './transport.mjs';

/**
 * Handles all Yivi state and state management logic for a given SAML request.
 */
class YiviSessionHandler {
    constructor({
        server,
        assertUrl,
        assertParameters,
        errorAssertUrl,
        sessionData,
        errorCallback,
        returningFailedCallback,
    }) {
        this._sessionData = JSON.parse(sessionData);
        this._assertUrl = assertUrl;
        this._assertParameters = assertParameters;
        this._errorAssertUrl = errorAssertUrl;
        this._errorCallback = errorCallback;
        this._returningFailedCallback = returningFailedCallback;
        this._options = {
            session: {
                url: server,
                start: false,
                mapping: {
                    sessionPtr: () => {
                        // Replace QR code to a path with our own hostname.
                        const regex = /irma\/session\/([^\/]+)$/;
                        const postfix = this._sessionData.sessionPtr.u.match(regex)[1];
                        this._sessionData.sessionPtr.u = `${server}/irma/session/${postfix}`;
                        return this._sessionData.sessionPtr;
                    }
                },
                result: {
                    url: (o) => `${o.url}/session/${this._sessionData.token}/result-jwt`,
                    // The JWT must be converted to a SAML assertion.
                    parseResponse: (resp) => resp.text()
                        .then((jwt) => this._performAssert(jwt))
                        .then((resp) => this._parseAssertResponse(resp)),
                },
            },
            state: {
                serverSentEvents: false, // Disable sse to prevent server errors to be generated.
            },
        };
    }

    async start(webPlugin, webOptions) {
        this._yiviCore = new YiviCore({ ...this._options, ...webOptions });
        this._yiviCore.use(webPlugin);
        this._yiviCore.use(YiviClient);

        // Fetching the error assertion when an error occurs is not included in YiviClient,
        // so we have to do this manually.
        try {
            const assert = await this._yiviCore.start()
            this._doReturn(assert);
        } catch (error) {
            await this.handleError();
        }
    }

    async abort() {
        if (this._yiviCore != null) this._yiviCore.abort();
        await this.handleErrorAbort();
    }

    async handleError() {
        try {
            this._errorCallback();
            const resp = await this._performErrorAssert();
            const assert = this._parseAssertResponse(resp);
            await this._doReturn(assert);
        } catch (err) {
            this._returningFailedCallback();
            throw err; // Re-throw error such that the error will be reported.
        }
    }

    async handleErrorAbort() {
        try {
            this._errorCallback();
            const resp = await this._performErrorAbortAssert();
            const assert = this._parseAssertResponse(resp);
            await this._doReturn(assert);
        } catch (err) {
            this._returningFailedCallback();
            throw err; // Re-throw error such that the error will be reported.
        }
    }

    _parseAssertResponse(assertResponse) {
        if (assertResponse.status !== 200) {
            throw new Error('Error response received while fetching assertion response');
        }
        if (!assertResponse.data.serviceUrl || !assertResponse.data.samlResponse) {
            throw new Error('Invalid assertion');
        }
        return assertResponse.data;
    }

    _performAssert(yiviResult) {
        return postJson(this._assertUrl, {
            'token': yiviResult,
            'parameters': this._assertParameters,
        });
    }

    _performErrorAssert() {
        return postJson(this._errorAssertUrl, {
            'parameters': this._assertParameters,
        });
    }

    _performErrorAbortAssert() {
        return postJson(this._errorAssertUrl + '/abort', {
            'parameters': this._assertParameters,
        });
    }

    _doReturn(assert) {
        // Result must be submitted as HTML form using a POST request.
        const form = document.createElement('form');
        document.body.appendChild(form);
        form.method = 'post';
        form.action = assert.serviceUrl;

        const addInput = (name, value) => {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = name;
            input.value = value;
            form.appendChild(input);
        };

        addInput('SAMLResponse', assert.samlResponse);
        if (assert.relayState) {
            addInput('RelayState', assert.relayState);
        }

        // Delay submitting of form to make sure the success animation is visible.
        setTimeout(() => form.submit(), 2000);

        // Add fallback handler in case returning to website did not work.
        setTimeout(() => {
            this._returningFailedCallback();
            throw 'Returning to website failed'; // Throw error to report the issue.
        }, 10000);
    }
}

export default YiviSessionHandler;
