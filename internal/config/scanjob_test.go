package config

import (
	"reflect"
	"testing"
)

// TestLoadScanJobReadsEveryField.
//
// Written because DataInImage was declared, checked by cmd/scanjob, and read
// from the environment by nothing: an edit adding the parsing silently did not
// apply, the field stayed false forever, and the symptom was a scan that
// crawled while three adapters tried to fetch data already beside them.
//
// A field nothing populates is indistinguishable from a field nobody set, which
// is why this compares against the zero value rather than trusting review.
func TestLoadScanJobReadsEveryField(t *testing.T) {
	t.Setenv("SECUREOPS_SCANNER_DATA_IN_IMAGE", "true")
	t.Setenv("SECUREOPS_WORKSPACE_ROOT", "/workspaces")
	t.Setenv("SECUREOPS_SCANNER_TIMEOUT", "3m")
	t.Setenv("SECUREOPS_FETCH_MAX_FILES", "1234")
	t.Setenv("SECUREOPS_GRYPE_DB_DIR", "/var/cache/grype/db")
	// Deliberately not the defaults. slog.LevelInfo is 0 and EnvDevelopment is
	// the fallback, so leaving either at its default would make the zero-value
	// check below unable to tell "read it" from "forgot it".
	t.Setenv("SECUREOPS_LOG_LEVEL", "debug")
	t.Setenv("SECUREOPS_ENV", "production")
	t.Setenv("SECUREOPS_LOG_FORMAT", "text")
	t.Setenv("SECUREOPS_SCANNER_MAX_OUTPUT_BYTES", "1048576")
	t.Setenv("SECUREOPS_FETCH_TIMEOUT", "4m")
	t.Setenv("SECUREOPS_FETCH_MAX_BYTES", "999999")

	cfg, err := LoadScanJob()
	if err != nil {
		t.Fatalf("LoadScanJob: %v", err)
	}

	if !cfg.DataInImage {
		t.Error("SECUREOPS_SCANNER_DATA_IN_IMAGE=true did not reach DataInImage")
	}
	if cfg.WorkspaceRoot != "/workspaces" {
		t.Errorf("WorkspaceRoot = %q", cfg.WorkspaceRoot)
	}
	if cfg.Fetch.MaxFiles != 1234 {
		t.Errorf("Fetch.MaxFiles = %d", cfg.Fetch.MaxFiles)
	}
	if cfg.Scanners.GrypeDBCacheDir == "" {
		t.Error("scanner settings are empty")
	}

	// Nothing may be left at its zero value with every variable set: a zero
	// here means a field the loader forgot, which is the defect above.
	v := reflect.ValueOf(cfg)
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if !f.IsExported() {
			continue
		}
		if v.Field(i).IsZero() {
			t.Errorf("ScanJob.%s is zero after loading a fully populated environment; "+
				"the loader does not read it", f.Name)
		}
	}
}

// TestDataInImageDefaultsToFalse.
//
// The safe default. A deployment that has not built the data into its image
// must still provision, and a flag that defaulted true would leave those
// scanners with no data and no attempt to get any.
func TestDataInImageDefaultsToFalse(t *testing.T) {
	t.Setenv("SECUREOPS_SCANNER_DATA_IN_IMAGE", "")
	cfg, err := LoadScanJob()
	if err != nil {
		t.Fatalf("LoadScanJob: %v", err)
	}
	if cfg.DataInImage {
		t.Error("DataInImage defaulted to true")
	}
}
