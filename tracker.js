/**
 * AAGS Universal Tracker — DEBUG VERSION
 * Remove console.logs after confirming tracking works
 */
(function() {
    'use strict';

    const API_URL = 'https://farm-aagsgithub-io.onrender.com/api';
    const SESSION_KEY = 'aags_track_session';
    const SOURCE_KEY = 'aags_track_source';

    console.log('═══════════════════════════════════');
    console.log('🚀 [AAGS Tracker] Starting...');
    console.log('📍 Host:', window.location.hostname);
    console.log('📍 Page:', window.location.pathname);
    console.log('═══════════════════════════════════');

    function getSessionId() {
        let sid = localStorage.getItem(SESSION_KEY);
        if (!sid) {
            sid = 'sess_' + Date.now().toString(36) + '_' +
                  Math.random().toString(36).substring(2, 10);
            localStorage.setItem(SESSION_KEY, sid);
            console.log('🆕 New session created:', sid);
        } else {
            console.log('♻️ Existing session:', sid);
        }
        return sid;
    }

    function detectSource() {
        let src = null;
        const hostname = window.location.hostname.toLowerCase();

        const urlParams = new URLSearchParams(window.location.search);
        const paramSrc = urlParams.get('src');
        if (paramSrc && ['quavo', 'zhus', 'iszo'].includes(paramSrc.toLowerCase())) {
            src = paramSrc.toLowerCase();
            console.log('🔍 Source from URL param:', src);
        }

        if (!src) {
            if (hostname.includes('aags-agricultural-q.netlify')) {
                src = 'quavo';
                console.log('🔍 Source detected from Q hostname:', src);
            } else if (hostname.includes('aags-agricultural-zh.netlify')) {
                src = 'zhus';
                console.log('🔍 Source detected from ZH hostname:', src);
            } else if (hostname.includes('aags-agricultural-isho.netlify')) {
                src = 'iszo';
                console.log('🔍 Source detected from ISHO hostname:', src);
            }
        }

        if (!src) {
            if (hostname.includes('quavo')) src = 'quavo';
            else if (hostname.includes('zhus')) src = 'zhus';
            else if (hostname.includes('iszo') || hostname.includes('isho')) src = 'iszo';
        }

        if (!src && document.referrer) {
            const ref = document.referrer.toLowerCase();
            if (ref.includes('aags-agricultural-q.netlify')) src = 'quavo';
            else if (ref.includes('aags-agricultural-zh.netlify')) src = 'zhus';
            else if (ref.includes('aags-agricultural-isho.netlify')) src = 'iszo';
        }

        if (!src) {
            src = localStorage.getItem(SOURCE_KEY);
            if (src) console.log('🔍 Source from storage:', src);
        }

        if (src) localStorage.setItem(SOURCE_KEY, src);
        return src || 'unknown';
    }

    const SESSION_ID = getSessionId();
    const SOURCE = detectSource();

    console.log('✅ Session ID:', SESSION_ID);
    console.log('✅ Source:', SOURCE);

    function getUserEmail() {
        try {
            const u = JSON.parse(localStorage.getItem('aags_user') || 'null');
            return u && u.email ? u.email : null;
        } catch (e) { return null; }
    }
    function getUserName() {
        try {
            const u = JSON.parse(localStorage.getItem('aags_user') || 'null');
            return u && u.name ? u.name : null;
        } catch (e) { return null; }
    }

    function getPageName() {
        const path = window.location.pathname;
        return path.substring(path.lastIndexOf('/') + 1) || 'index.html';
    }

    function sendPageView() {
        const payload = {
            session_id: SESSION_ID,
            source_key: SOURCE,
            page: getPageName(),
            referrer: document.referrer || null,
            user_agent: navigator.userAgent,
            email: getUserEmail(),
            full_name: getUserName()
        };

        console.log('📤 Sending visit:', payload);

        fetch(`${API_URL}/track/visit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(r => r.json())
        .then(data => {
            console.log('✅ Visit response:', data);
        })
        .catch(err => {
            console.error('❌ Visit failed:', err);
        });
    }

    function trackEvent(eventType, eventLabel, metadata) {
        const payload = {
            session_id: SESSION_ID,
            source_key: SOURCE,
            event_type: eventType,
            event_label: eventLabel || eventType,
            page: getPageName(),
            metadata: metadata || {},
            email: getUserEmail(),
            full_name: getUserName()
        };

        console.log('📤 Sending click:', payload);

        fetch(`${API_URL}/track/click`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(r => r.json())
        .then(data => {
            console.log('✅ Click response:', data);
        })
        .catch(err => {
            console.error('❌ Click failed:', err);
        });
    }

    window.AAGSTracker = {
        track: trackEvent,
        sessionId: SESSION_ID,
        source: SOURCE
    };

    function autoTrackClicks() {
        document.body.addEventListener('click', function(e) {
            const el = e.target.closest('a, button, [data-track]');
            if (!el) return;

            const explicitTrack = el.getAttribute('data-track');
            if (explicitTrack) {
                trackEvent(explicitTrack, el.textContent.trim().slice(0, 80));
                return;
            }

            const text = (el.textContent || '').trim().toLowerCase();
            const href = el.getAttribute('href') || '';

            if (text.includes('login') || href.includes('login.html')) { trackEvent('click_login', 'Clicked Login'); return; }
            if (text.includes('sign up') || href.includes('signup.html')) { trackEvent('click_signup', 'Clicked Sign Up'); return; }
            if (text.includes('apply for grant') || (text.includes('apply now') && href.includes('grant'))) { trackEvent('click_apply_grant', 'Apply for Grant'); return; }
            if (text.includes('apply for loan') || (text.includes('apply now') && href.includes('loan'))) { trackEvent('click_apply_loan', 'Apply for Loan'); return; }
            if (text.includes('download') && (text.includes('form') || href.includes('.pdf'))) { trackEvent('click_download_form', 'Download Form'); return; }
            if (text.includes('proceed') && text.includes('payment')) { trackEvent('click_proceed_payment', 'Proceed with Payment'); return; }
            if (text.includes('sent the money')) { trackEvent('click_sent_money', 'I Have Sent the Money'); return; }
            if (text.includes('payment later')) { trackEvent('click_payment_later', 'Continue with Payment Later'); return; }
            if (text.includes('contact support') || href.includes('support')) { trackEvent('click_support', 'Contact Support'); return; }
            if (el.tagName === 'A' && href && !href.startsWith('#')) { trackEvent('click_link', text.slice(0, 80) || href, { href }); }
        }, true);
    }

    function handleUrlEvent() {
        const urlParams = new URLSearchParams(window.location.search);
        const ev = urlParams.get('event');
        if (ev) trackEvent(ev, ev);
    }

    function init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function() {
                console.log('📄 DOM ready — sending page view');
                sendPageView();
                autoTrackClicks();
                handleUrlEvent();
            });
        } else {
            console.log('📄 DOM already loaded — sending page view');
            sendPageView();
            autoTrackClicks();
            handleUrlEvent();
        }
    }

    init();

})();
