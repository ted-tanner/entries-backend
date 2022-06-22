/* jshint esversion: 6 */

const PAGE_LOAD_FADE_IN_DURATION = 1650;
const PAGE_LOAD_FADE_IN_INTERVAL = 400;

const SCROLL_FADE_IN_DURATION = 1250;
const SCROLL_FADE_IN_INTERVAL = 400;

const QUICK_SCROLL_FADE_IN_DURATION = 1000;
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

function resizeText(textResizeDescriptors) {
    textResizeDescriptors.forEach(descriptor => {
        let elements = document.getElementsByClassName(descriptor.cssClass);

        for (let element of elements) {
            if (window.innerWidth > WRAP_AFTER_WIDTH)
                element.style.fontSize = ((Math.min(window.innerWidth,
                                                    MAX_SCALE_WIDTH) / 10) * descriptor.scale) + 'px';

            if (descriptor.leftPadding !== null)
                element.style.marginLeft = (3 * (window.innerWidth / 10) * descriptor.leftPadding) + 'px';
        }
    });
}

function fadeInElement(element, fadeInDuration) {    
    element.style.opacity = 0;
    element.style.display = "block";
    
    let start = null;
    let fadeInDurationSquared = fadeInDuration * fadeInDuration;
    
    function fadeInStep(timestamp) {
        if (start === null)
            start = timestamp;

        let elapsed = timestamp - start;
        let percentOpacity = Math.min((elapsed * elapsed) / fadeInDurationSquared, 1);

        element.style.opacity = percentOpacity;

        if (percentOpacity !== 1)
            window.requestAnimationFrame(fadeInStep);
    }

    window.requestAnimationFrame(fadeInStep);
}

function fadeInByGroup(cssClassName, fadeInDuration, fadeInInterval) {
    if (areElementsLoading) {
        setTimeout(() => { fadeInByGroup(cssClassName, fadeInDuration, fadeInInterval); }, 200);
        return;
    }

    areElementsLoading = true;
    let elements = document.getElementsByClassName(cssClassName);

    for (let i = 0; i < elements.length; ++i) {
        setTimeout(() => {
            fadeInElement(elements[i], fadeInDuration);
        }, fadeInInterval * i);
    }

    setTimeout(() => { areElementsLoading = false; }, fadeInInterval * (elements.length - 1));
}

function ensurePageIsScrollable() {
    let mainDocument = document.getElementById('main-document');

    while (mainDocument.offsetHeight <= window.innerHeight) {
        let br = document.createElement('br');
        mainDocument.appendChild(br);
        extraLineBreaks.push(br);
    }

    while (mainDocument.offsetHeight > window.innerHeight && extraLineBreaks.length > 0)
        mainDocument.removeChild(extraLineBreaks.pop());
}

window.addEventListener('load', () => {
    let phoneImage = document.getElementById('iphone-img');
    let phoneImageNewSrc = phoneImage.getAttribute(
        window.matchMedia('(prefers-color-scheme: dark)').matches ?
            'dark-mode-img' :
            'light-mode-img');

    phoneImage.setAttribute('src', phoneImageNewSrc);


    resizeText(defaultTextResizeDescriptors);
    fadeInByGroup(FADE_IN_ON_LOAD_CLASS, PAGE_LOAD_FADE_IN_DURATION, PAGE_LOAD_FADE_IN_INTERVAL);

    let bottomLineBreaksDiv = document.getElementById('bottom-line-breaks');
    for (let i = 0; i < ENDING_LINE_BREAKS_COUNT; ++i)
        bottomLineBreaksDiv.appendChild(document.createElement('br'));

    ensurePageIsScrollable();

    console.log('Happy budgeting!');
}, false);

window.onscroll = () => {
    if (!userHasScrolled) {
        userHasScrolled = true;

        fadeInByGroup(FADE_IN_ON_SCROLL_CLASS, SCROLL_FADE_IN_DURATION, SCROLL_FADE_IN_INTERVAL);
        setTimeout(() => {
            fadeInByGroup(QUICK_FADE_IN_ON_SCROLL_CLASS,
                          QUICK_SCROLL_FADE_IN_DURATION,
                          QUICK_SCROLL_FADE_IN_INTERVAL);
        }, SCROLL_FADE_IN_DURATION / 1.5);
    }
    ensurePageIsScrollable();
};

window.addEventListener("resize", () => {
    resizeText(defaultTextResizeDescriptors);
    ensurePageIsScrollable();
});
