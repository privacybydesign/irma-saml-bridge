import nl from '../translations/nl';
import en from '../translations/en';

const translations = {
    en,
    nl
};

const translate = (language, key) => {
    const currentTranslation = {...en, ...translations[language]};
    const text = currentTranslation[key];

    if (!text) {
        return `? ${key} ?`;
    }

    return text;
};

export default translate;
