// services/syncScheduler.js
const cron = require('node-cron');
const { fetchAgriculturalGrants, normalizeGrant } = require('./grantsService');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

async function syncGrants() {
    const startedAt = new Date();
    console.log(`[Sync] Starting grant sync at ${startedAt.toISOString()}`);

    try {
        const rawGrants = await fetchAgriculturalGrants({ rows: 200 });
        console.log(`[Sync] Fetched ${rawGrants.length} grants from Grants.gov`);

        const normalized = rawGrants.map(normalizeGrant).filter(g => g.external_id);

        // Upsert by external_id
        const { error } = await supabase
            .from('grants')
            .upsert(normalized, { onConflict: 'external_id' });

        if (error) throw error;

        // Mark grants as closed if their close_date is past
        await supabase
            .from('grants')
            .update({ status: 'CLOSED' })
            .lt('close_date', new Date().toISOString())
            .neq('status', 'CLOSED');

        // Log successful sync
        await supabase.from('sync_log').insert([{
            source: 'Grants.gov',
            status: 'success',
            records_synced: normalized.length,
            started_at: startedAt.toISOString(),
            completed_at: new Date().toISOString()
        }]);

        console.log(`[Sync] ✅ Synced ${normalized.length} grants successfully`);
        return { success: true, count: normalized.length };
    } catch (err) {
        console.error('[Sync] ❌ Sync failed:', err.message);

        await supabase.from('sync_log').insert([{
            source: 'Grants.gov',
            status: 'failed',
            error_message: err.message,
            started_at: startedAt.toISOString(),
            completed_at: new Date().toISOString()
        }]);

        return { success: false, error: err.message };
    }
}

// Schedule: every 6 hours (0 min, every 6th hour)
function startScheduler() {
    cron.schedule('0 */6 * * *', syncGrants);
    console.log('[Scheduler] Grant sync scheduled every 6 hours');

    // Run once on startup after 30s delay
    setTimeout(syncGrants, 30000);
}

module.exports = { syncGrants, startScheduler };
