const PAGE_LOAD_FADE_IN_DURATION = 1650;
const PAGE_LOAD_FADE_IN_INTERVAL = 400;

const SCROLL_FADE_IN_DURATION = 1650;
const SCROLL_FADE_IN_INTERVAL = 400;

const QUICK_SCROLL_FADE_IN_DURATION = 600;
const QUICK_SCROLL_FADE_IN_INTERVAL = 350;

const FADE_IN_ON_LOAD_CLASS = 'fade-in-on-load';
const FADE_IN_ON_SCROLL_CLASS = 'fade-in-on-scroll';
const QUICK_FADE_IN_ON_SCROLL_CLASS = 'quick-fade-in-after-scroll';

const HUGE_SCALE = 0.8;
const LARGE_SCALE = 0.42;
const MODERATE_SCALE = 0.32;
const SMALL_SCALE = 0.24;

const HUGE_TEXT_CLASS = 'huge-size-text';
const LARGE_TEXT_CLASS = 'large-size-text';
const MODERATE_TEXT_CLASS = 'moderate-size-text';
const SMALL_TEXT_CLASS = 'small-size-text';

const ENDING_LINE_BREAKS_COUNT = 4;
const CITATION_SHIFT = 0.18;
const WRAP_AFTER_WIDTH = 750;
const MAX_SCALE_WIDTH = 1300;

const LIGHT_PHONE_IMG_NAME = 'budget-app-light.png';
const DARK_PHONE_IMG_NAME = 'budget-app-dark.png';

class TextResizeDescriptor {
    constructor(cssClass, scale, leftPadding) {
        this.cssClass = cssClass;
        this.scale = scale;
        this.leftPadding = leftPadding;
    }
}

const defaultTextResizeDescriptors = [
    new TextResizeDescriptor(HUGE_TEXT_CLASS, HUGE_SCALE, null),
    new TextResizeDescriptor(LARGE_TEXT_CLASS, LARGE_SCALE, null),
    new TextResizeDescriptor(MODERATE_TEXT_CLASS, MODERATE_SCALE, null),
    new TextResizeDescriptor(SMALL_TEXT_CLASS, SMALL_SCALE, CITATION_SHIFT),
];

const extraLineBreaks = [];
let userHasScrolled = false;
let areElementsLoading = false;

let _resizeText = (textResizeDescriptors) => {
    textResizeDescriptors.forEach(descriptor => {
        let elements = document.getElementsByClassName(descriptor.cssClass);

        for (element of elements) {
            if ($(window).width() > WRAP_AFTER_WIDTH) {
                element.style.fontSize = ((Math.min($(window).width(), MAX_SCALE_WIDTH) / 10) * descriptor.scale) + 'px';
            }

            if (descriptor.leftPadding !== null) {
                element.style.marginLeft = (3 * ($(window).width() / 10) * descriptor.leftPadding) + 'px';
            }
        }
    });
}

let _fadeInByGroup = (cssClassName, fadeInDuration, fadeInInterval) => {
    if (areElementsLoading) {
        setTimeout(() => { _fadeInByGroup(cssClassName, fadeInDuration, fadeInInterval); }, 200);
        return;
    }

    areElementsLoading = true;
    let fadeInElements = document.getElementsByClassName(cssClassName);

    for (let i = 0; i < fadeInElements.length; ++i) {
        fadeInElements[i].classList.add('___fade-in-group-' + i);
    }

    for (let i = 0; i < fadeInElements.length; ++i) {
        setTimeout(() => {
            $('.___fade-in-group-' + i).fadeIn(fadeInDuration).removeClass('___fade-in-group-' + i);
        }, fadeInInterval * i);
    }

    setTimeout(() => { areElementsLoading = false; }, fadeInInterval * (fadeInElements.length - 1));
}

let _ensurePageIsScrollable = () => {
    let mainDocument = document.getElementById('main-document');

    while (mainDocument.offsetHeight <= $(window).height()) {
        let br = document.createElement('br');
        mainDocument.appendChild(br);
        extraLineBreaks.push(br);
    }

    while (mainDocument.offsetHeight > $(window).height() && extraLineBreaks.length > 0) {
        mainDocument.removeChild(extraLineBreaks.pop());
    }
}

let _replaceFinalSegmentInUri = (uri, newSegment) => {
    return uri.substr(0, uri.lastIndexOf('/') + 1) + newSegment;
}

$(document).ready(() => {
    if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        let phoneImage = document.getElementById('iphone-img');
        let phoneImageSrc = phoneImage.getAttribute('src');
        let phoneImageNewSrc = _replaceFinalSegmentInUri(phoneImageSrc, DARK_PHONE_IMG_NAME);

        phoneImage.setAttribute('src', phoneImageNewSrc);
    }

    _resizeText(defaultTextResizeDescriptors);
    _fadeInByGroup(FADE_IN_ON_LOAD_CLASS, PAGE_LOAD_FADE_IN_DURATION, PAGE_LOAD_FADE_IN_INTERVAL);

    let bottomLineBreaksDiv = document.getElementById('bottom-line-breaks');
    for (let i = 0; i < ENDING_LINE_BREAKS_COUNT; ++i) {
        bottomLineBreaksDiv.appendChild(document.createElement('br'));
    }

    _ensurePageIsScrollable();

    console.log('Happy budgeting!');
});

$(window).scroll(() => {
    if (!userHasScrolled) {
        userHasScrolled = true;

        _fadeInByGroup(FADE_IN_ON_SCROLL_CLASS, SCROLL_FADE_IN_DURATION, SCROLL_FADE_IN_INTERVAL);
        setTimeout(() => {
            _fadeInByGroup(QUICK_FADE_IN_ON_SCROLL_CLASS, QUICK_SCROLL_FADE_IN_DURATION, QUICK_SCROLL_FADE_IN_INTERVAL);
        }, SCROLL_FADE_IN_DURATION / 1.5);
    }
    _ensurePageIsScrollable();
});

$(window).resize(() => {
    _resizeText(defaultTextResizeDescriptors);
    _ensurePageIsScrollable();
});
