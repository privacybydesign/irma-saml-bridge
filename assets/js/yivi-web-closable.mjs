import YiviWeb from '@privacybydesign/yivi-web';

/**
 * Extension of YiviWeb plugin that responds on the close button.
 * YiviWeb is not a React component, so our extension is not one either.
 * We cannot use JavaScript's 'extends' operator, because parcel-bundler does not support this.
 */
class YiviWebClosable {
    constructor({ stateMachine, options }) {
        this._yiviWeb = new YiviWeb({stateMachine, options: {...options, showCloseButton: true}});

        // Since we don't use yivi-popup, we have to handle events to the close button ourselves.
        const closeButton = document.querySelector(options.element).querySelector('.yivi-web-close');
        closeButton.addEventListener('click', () => {
            closeButton.style.display = 'none';
            stateMachine.selectTransition(({validTransitions}) =>
                validTransitions.includes('abort') ? {transition: 'abort'} : false
            );
        });
    }

    stateChange(state) {
        this._yiviWeb.stateChange(state);
    }

    close() {
        return this._yiviWeb.close();
    }
}

export default YiviWebClosable;
