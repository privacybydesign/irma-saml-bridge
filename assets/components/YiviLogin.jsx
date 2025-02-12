import React from 'react';

import YiviSessionHandler from '../js/yivi';
import YiviWebClosable from '../js/yivi-web-closable.mjs';
import translate from '../js/translate';

import '@privacybydesign/yivi-css';
import '../css/sidnyivi.css';

class YiviLogin extends React.Component {

    constructor(props) {
        super(props);
        this.state = {
            hasError: !!this.props.error,
            returningFailed: false,
        };
        this._yiviSessionHandler = new YiviSessionHandler({
            server: props.server,
            assertUrl: props.assertUrl,
            assertParameters: props.assertParameters,
            errorAssertUrl: props.errorAssertUrl,
            sessionData: props.sessionData,
            errorCallback: () => this.setState({hasError: true}),
            returningFailedCallback: () => this.setState({returningFailed: true}),
        });
    }

    componentDidMount() {
        if (this.state.hasError) {
            this._yiviSessionHandler.handleError();
        } else {
            this._yiviSessionHandler.start(YiviWebClosable, {
                element: '#yivi-web-form',
                language: this.props.language,
                translations: {
                    success: translate(this.props.language, 'returning'),
                },
            });
        }
    }

    componentWillUnmount() {
        this._yiviSessionHandler.abort();
    }

    // The irma-frontend-packages are not very flexible with error handling, so in some cases
    // we have to render the error manually.
    // https://github.com/privacybydesign/irma-frontend-packages/issues/49
    _renderError() {
        return <section className="yivi-web-form">
            <div className="yivi-web-header">
                <p>
                    {translate(this.props.language, 'loginUnsuccessful')}
                </p>
            </div>
            <div className="yivi-web-content">
                <div className="yivi-web-centered">
                    <div className="yivi-web-forbidden-animation"/>
                    <p>
                        {translate(this.props.language, this.state.returningFailed ? 'errorReturningFailed' : 'error')}
                    </p>
                    {this.state.returningFailed
                        ?
                        <p>
                            {translate(this.props.language, 'errorPersists')}
                            <a href="mailto:support@yivi.app">support@yivi.app</a>
                        </p>
                        : null
                    }
                </div>
            </div>
        </section>
    }

    render() {
        // The yivi-web-form is managed by a non-react component, so we have to explicitly reset it when re-rendering.
        const form = document.querySelector('#yivi-web-form');
        if (form != null) form.innerHTML = '';
        return <div className="yivi-modal">
            {this.state.hasError || this.state.returningFailed
                ? this._renderError()
                : <section id="yivi-web-form"/>
            }
        </div>;
    }
}

export default YiviLogin;
