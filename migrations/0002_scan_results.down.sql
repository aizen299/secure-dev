-- Rollback of 0002_scan_results.

DROP TRIGGER IF EXISTS scan_scanner_results_set_updated_at ON scan_scanner_results;

DROP TABLE IF EXISTS scan_raw_results;
DROP TABLE IF EXISTS scan_scanner_results;

DROP TYPE IF EXISTS scanner_result_status;
