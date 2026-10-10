/**
 * AAGS Universal Tracker
 * Include on every page: <script src="tracker.js"></script>
 * Tracks: page views, source (Quavo/Zhus/Iszo), clicks, user journey
 */
(function() {
    'use strict';

    // ============================================================
    // CONFIG
    // ============================================================
    const API_URL = 'https://farm-aagsgithub-io.onrender.com/api';
    const SESSION_KEY = 'aags_track_session';
    const SOURCE_KEY = 'aags_track_source';

    // ============================================================
    // SESSION ID (persistent per browser)
    // ============================================================
    function getSessionId() {
        let sid = localStorage.getItem(SESSION_KEY);
        if (!sid) {
            sid = 'sess_' + Date.now().toString(36) + '_' +
                  Math.random().toString(36).substring(2, 10);
            localStorage.setItem(SESSION_KEY, sid);
        }
        return sid;
    }

    // ============================================================
    // SOURCE DETECTION (Quavo / Zhus / Iszo)
    // ============================================================
    function detectSource() {
        // 1. URL query param: ?src=quavo
        const urlParams = new URLSearchParams(window.location.search);
        let src = urlParams.get('src');

        // 2. Subdomain detection: quavo.example.com
        if (!src) {
            const host = window.location.hostname.toLowerCase();
            if (host.includes('quavo')) src = 'quavo';
            else if (host.includes('zhus')) src = 'zhus';
            else if (host.includes('iszo')) src = 'iszo';
        }

        // 3. Referrer detection
        if (!src && document.referrer) {
            const ref = document.referrer.toLowerCase();
            if (ref.includes('quavo') || ref.includes('farmer1')) src = 'quavo';
            else if (ref.includes('zhus') || ref.includes('farmer2')) src = 'zhus';
            else if (ref.includes('iszo') || ref.includes('farmer3')) src = 'iszo';
        }

        // 4. Use previously stored source (sticky per session)
        if (!src) {
            src = localStorage.getItem(SOURCE_KEY);
        }

        if (src) {
            localStorage.setItem(SOURCE_KEY, src);
        }
        return src || 'unknown';
    }

    const SESSION_ID = getSessionId();
    const SOURCE = detectSource();

    // ============================================================
    // CURRENT USER (if logged in)
    // ============================================================
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

    // ============================================================
    // TRACK PAGE VIEW
    // ============================================================
    function getPageName() {
        const path = window.location.pathname;
        const page = path.substring(path.lastIndexOf('/') + 1) || 'index.html';
        return page;
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

        fetch(`${API_URL}/track/visit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            keepalive: true
        }).catch(() => {});
    }

    // ============================================================
    // TRACK CLICK / EVENT
    // ============================================================
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

        fetch(`${API_URL}/track/click`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            keepalive: true
        }).catch(() => {});
    }

    // Expose globally so other pages can call it
    window.AAGSTracker = {
        track: trackEvent,
        sessionId: SESSION_ID,
        source: SOURCE
    };

    // ============================================================
    // AUTO TRACK KNOWN CLICKS
    // ============================================================
    function autoTrackClicks() {
        document.body.addEventListener('click', function(e) {
            const el = e.target.closest('a, button, [data-track]');
            if (!el) return;

            // Explicit data-track attribute wins
            const explicitTrack = el.getAttribute('data-track');
            if (explicitTrack) {
                trackEvent(explicitTrack, el.textContent.trim().slice(0, 80));
                return;
            }

            const text = (el.textContent || '').trim().toLowerCase();
            const href = el.getAttribute('href') || '';

            // Login button
            if (text.includes('login') || href.includes('login.html')) {
                trackEvent('click_login', 'Clicked Login');
                return;
            }

            // Signup button
            if (text.includes('sign up') || href.includes('signup.html')) {
                trackEvent('click_signup', 'Clicked Sign Up');
                return;
            }

            // Apply for Grant
            if (text.includes('apply for grant') || text.includes('apply now')) {
                if (href.includes('grant')) {
                    trackEvent('click_apply_grant', 'Apply for Grant');
                    return;
                }
                if (href.includes('loan')) {
                    trackEvent('click_apply_loan', 'Apply for Loan');
                    return;
                }
            }

            // Loan
            if (text.includes('loan') || href.includes('loan')) {
                trackEvent('click_loan', 'Loan clicked');
                return;
            }

            // Download Form
            if (text.includes('download') && (text.includes('form') || href.includes('.pdf'))) {
                trackEvent('click_download_form', 'Download Form');
                return;
            }

            // Proceed with Payment
            if (text.includes('proceed') && text.includes('payment')) {
                trackEvent('click_proceed_payment', 'Proceed with Payment');
                return;
            }

            // I have sent the money
            if (text.includes('sent the money')) {
                trackEvent('click_sent_money', 'I Have Sent the Money');
                return;
            }

            // Continue with payment later
            if (text.includes('payment later')) {
                trackEvent('click_payment_later', 'Continue with Payment Later');
                return;
            }

            // Contact Support
            if (text.includes('contact support') || href.includes('support')) {
                trackEvent('click_support', 'Contact Support');
                return;
            }

            // Generic link click
            if (el.tagName === 'A' && href && !href.startsWith('#')) {
                trackEvent('click_link', text.slice(0, 80) || href, { href });
            }
        }, true);
    }

    // ============================================================
    // HANDLE PAGE-SPECIFIC EVENTS (via URL params or global calls)
    // ============================================================
    // If page URLs include: ?event=signup_complete
    // the tracker will fire the event automatically.
    function handleUrlEvent() {
        const urlParams = new URLSearchParams(window.location.search);
        const ev = urlParams.get('event');
        if (ev) {
            trackEvent(ev, ev);
        }
    }

    // ============================================================
    // INIT
    // ============================================================
    function init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function() {
                sendPageView();
                autoTrackClicks();
                handleUrlEvent();
            });
        } else {
            sendPageView();
            autoTrackClicks();
            handleUrlEvent();
        }
    }

    init();

    console.log('[AAGS Tracker] Session:', SESSION_ID, '| Source:', SOURCE);

})();
