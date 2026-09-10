// services/grantsService.js
const fetch = require('node-fetch');

const GRANTS_GOV_API = 'https://api.grants.gov/v1/api/search2';
const FETCH_DETAIL_API = 'https://api.grants.gov/v1/api/fetchOpportunity';

// Agriculture category code from Grants.gov = "AG"
const AGRICULTURE_CATEGORY = 'AG';

async function fetchAgriculturalGrants({ startRecord = 0, rows = 100 } = {}) {
    const body = {
        keyword: '',
        oppStatuses: 'posted|forecasted|closed',
        fundingCategories: AGRICULTURE_CATEGORY, // Agriculture only
        rows,
        startRecord
    };

    const res = await fetch(GRANTS_GOV_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        timeout: 30000
    });

    if (!res.ok) throw new Error(`Grants.gov returned ${res.status}`);

    const data = await res.json();
    return data?.data?.oppHits || [];
}

async function fetchGrantDetails(opportunityId) {
    const res = await fetch(FETCH_DETAIL_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ opportunityId }),
        timeout: 30000
    });

    if (!res.ok) throw new Error(`Grants.gov detail returned ${res.status}`);
    const data = await res.json();
    return data?.data || null;
}

// Normalize raw Grants.gov record to AAGS schema
function normalizeGrant(raw) {
    const now = new Date().toISOString();
    const closeDate = raw.closeDate ? new Date(raw.closeDate) : null;
    const openDate = raw.openDate ? new Date(raw.openDate) : null;

    let status = 'OPEN';
    if (closeDate && closeDate < new Date()) status = 'CLOSED';
    else if (openDate && openDate > new Date()) status = 'UPCOMING';
    else if (closeDate && (closeDate - new Date()) < 30 * 24 * 60 * 60 * 1000) status = 'CLOSING_SOON';

    return {
        external_id: String(raw.id),
        opportunity_number: raw.number || null,
        title: raw.title || 'Untitled Opportunity',
        agency: raw.agencyName || raw.agencyCode || 'Unknown',
        agency_code: raw.agencyCode || null,
        description: raw.description || null,
        award_ceiling: raw.awardCeiling || null,
        award_floor: raw.awardFloor || null,
        close_date: closeDate ? closeDate.toISOString() : null,
        open_date: openDate ? openDate.toISOString() : null,
        status,
        source: 'Grants.gov',
        source_url: `https://www.grants.gov/search-results-detail/${raw.id}`,
        application_url: `https://www.grants.gov/search-results-detail/${raw.id}`,
        raw_payload: raw,
        last_synced_at: now
    };
}

module.exports = { fetchAgriculturalGrants, fetchGrantDetails, normalizeGrant };
